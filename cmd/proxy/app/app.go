// Ligolo-ng
// Copyright (C) 2025 Nicolas Chatelain (nicocha30)

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package app

import (
	"context"
    cryptorand "crypto/rand"
    mathrand "math/rand" 
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/nicocha30/ligolo-ng/cmd/proxy/config"
	"github.com/nicocha30/ligolo-ng/pkg/proxy/netinfo"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/desertbit/grumble"
	"github.com/hashicorp/yamux"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/nicocha30/ligolo-ng/pkg/controller"
	"github.com/nicocha30/ligolo-ng/pkg/proxy"
	"github.com/nicocha30/ligolo-ng/pkg/proxy/netstack"
	"github.com/sirupsen/logrus"
)

var AgentList map[int]*controller.LigoloAgent
var AgentListMutex sync.Mutex
var ProxyController *controller.Controller

// CurrentAgentID points to the selected agent in the UI (when running session)
var CurrentAgentID int

// Store AgentIDs
var AgentCounter int

var (
	ErrInvalidAgent   = errors.New("please, select an agent using the session command")
	ErrAlreadyRunning = errors.New("already running")
	ErrNotRunning     = errors.New("no tunnel started")
)

func init() {
    // Seed the random number generator for port selection
    mathrand.Seed(time.Now().UnixNano())
}

func genRandomUUID() string {
    b := make([]byte, 8)
    _, err := cryptorand.Read(b)  // Changed from rand.Read
    if err != nil {
        logrus.Fatal(err)
    }
    return hex.EncodeToString(b)
}

// Helper function to check if a port is in use on an agent
func isPortInUse(agent *controller.LigoloAgent, port int) bool {
	for _, listener := range agent.Listeners {
		if listener != nil {
			_, listenerPort, err := net.SplitHostPort(listener.ListenerAddr())
			if err == nil && listenerPort == fmt.Sprintf("%d", port) {
				return true
			}
		}
	}
	return false
}

// Smart port allocation using ephemeral range with fallback
func findAvailablePort(agent *controller.LigoloAgent, preferredStart int) int {
	// If a preferred start port was given, try it first
	if preferredStart > 0 && !isPortInUse(agent, preferredStart) {
		return preferredStart
	}
	
	// Try random ephemeral ports (49152-60151) - looks like natural reverse connections
	for attempts := 0; attempts < 50; attempts++ {
		port := 49152 + mathrand.Intn(11000)
		if !isPortInUse(agent, port) {
			return port
		}
	}
	
	// Fallback: sequential search in backup range (45000-48999)
	for port := 45000; port < 49000; port++ {
		if !isPortInUse(agent, port) {
			logrus.Debugf("Using fallback port %d (ephemeral range exhausted)", port)
			return port
		}
	}
	
	// Fallback 2: try the 30000-34999 range
	for port := 30000; port < 35000; port++ {
		if !isPortInUse(agent, port) {
			logrus.Warnf("Using last-resort port %d (all preferred ranges exhausted)", port)
			return port
		}
	}
	
	// If we still can't find a port, there is another problem
	logrus.Errorf("Could not find available port after extensive search")
	return 30000 // Return something, but this will likely fail
}

func RegisterAgent(agent *controller.LigoloAgent) error {
	AgentListMutex.Lock()
	defer AgentListMutex.Unlock()
	var recovered bool

	// FOOLPROOF PIVOT CHAIN DETECTION
	remoteAddr := agent.Session.RemoteAddr().String()
	remoteHost, remotePort, _ := net.SplitHostPort(remoteAddr)
	
	// Also get the LOCAL address (proxy side)
	localAddr := agent.Session.LocalAddr().String()
	localHost, localPort, _ := net.SplitHostPort(localAddr)
	
	logrus.Debugf("New agent connecting - Remote: %s:%s, Local (proxy): %s:%s", 
		remoteHost, remotePort, localHost, localPort)
	
	// Strategy 1: Check if remoteHost matches an agent IP with a listener on remotePort
	// This handles: Agent connects directly to another agent's listener
	var parentAgent *controller.LigoloAgent
	var parentAgentID int
	var parentListener *proxy.LigoloListener
	
	for agentID, existingAgent := range AgentList {
		if !existingAgent.Alive() {
			continue
		}
		
		// Build a map of all IPs this agent has
		agentIPs := make(map[string]bool)
		for _, ifaceInfo := range existingAgent.Network {
			for _, address := range ifaceInfo.Addresses {
				ip, _, err := net.ParseCIDR(address)
				if err != nil {
					continue
				}
				agentIPs[ip.String()] = true
			}
		}
		
		// Check if this agent owns the remote IP
		if agentIPs[remoteHost] {
			// Check if this agent has a listener on the remote port
			for _, listener := range existingAgent.Listeners {
				if listener == nil {
					continue
				}
				
				_, listenerPort, err := net.SplitHostPort(listener.ListenerAddr())
				if err != nil {
					continue
				}
				
				if listenerPort == remotePort {
					// EXACT MATCH: This agent owns this IP and has a listener on this port
					parentAgent = existingAgent
					parentAgentID = agentID
					parentListener = listener
					break
				}
			}
		}
		
		if parentAgent != nil {
			break
		}
	}
	
	// Strategy 2: If remoteHost is the proxy IP or localhost, check for listeners redirecting to proxy
	// This handles: Agent connects through pivots that redirect back to proxy
	if parentAgent == nil && (remoteHost == localHost || remoteHost == "127.0.0.1" || remoteHost == "::1") {
		logrus.Debugf("Connection from proxy/localhost IP (%s), checking for redirect chains", remoteHost)
		
		// Find all listeners that could be in the chain
		type listenerInfo struct {
			agentID  int
			agent    *controller.LigoloAgent
			listener *proxy.LigoloListener
		}
		
		// Build a map of "destination" -> "listener that redirects there"
		redirectsTo := make(map[string]listenerInfo)
		
		for agentID, existingAgent := range AgentList {
			if !existingAgent.Alive() {
				continue
			}
			
			// Get all IPs for this agent
			agentIPs := []string{}
			for _, ifaceInfo := range existingAgent.Network {
				for _, address := range ifaceInfo.Addresses {
					ip, _, err := net.ParseCIDR(address)
					if err != nil {
						continue
					}
					if !ip.IsLoopback() {
						agentIPs = append(agentIPs, ip.String())
					}
				}
			}
			
			for _, listener := range existingAgent.Listeners {
				if listener == nil {
					continue
				}
				
				info := listenerInfo{
					agentID:  agentID,
					agent:    existingAgent,
					listener: listener,
				}
				
				// Map: what does this listener redirect TO?
				redirectAddr := listener.RedirectAddr()
				redirectsTo[redirectAddr] = info
				
				logrus.Debugf("Mapped listener: %s on %s -> redirects to %s", 
					listener.ListenerAddr(), existingAgent.Name, redirectAddr)
			}
		}
		
		// Find listeners that redirect to the proxy's listening port
		// The connection might show an ephemeral source port, but we care about
		// where the listener is redirecting TO (the proxy's actual listening port)
		proxyListenPort := localPort
		
		// Check all possible proxy addresses
		var proxyTargets []string
		proxyTargets = append(proxyTargets, fmt.Sprintf("%s:%s", localHost, proxyListenPort))
		proxyTargets = append(proxyTargets, fmt.Sprintf("0.0.0.0:%s", proxyListenPort))
		proxyTargets = append(proxyTargets, fmt.Sprintf("127.0.0.1:%s", proxyListenPort))
		proxyTargets = append(proxyTargets, fmt.Sprintf(":::%s", proxyListenPort))
		proxyTargets = append(proxyTargets, fmt.Sprintf("[::]:%s", proxyListenPort))
		
		// Find any listener redirecting to the proxy
		var directParentInfo *listenerInfo
		for _, target := range proxyTargets {
			if info, ok := redirectsTo[target]; ok {
				logrus.Debugf("Found listener on %s redirecting to proxy at %s", info.agent.Name, target)
				directParentInfo = &info
				break
			}
		}
		
		if directParentInfo != nil {
			// Found the direct parent - now walk backwards to find the complete chain
			var chain []listenerInfo
			chain = append(chain, *directParentInfo)
			visited := make(map[string]bool)
			currentAgent := directParentInfo.agent
			currentListener := directParentInfo.listener
			
			// Continue walking backwards from this listener
			for {
				listenerHost, listenerPort, err := net.SplitHostPort(currentListener.ListenerAddr())
				if err != nil {
					break
				}
				
				// Get all IPs for the current agent
				agentIPs := []string{}
				for _, ifaceInfo := range currentAgent.Network {
					for _, address := range ifaceInfo.Addresses {
						ip, _, err := net.ParseCIDR(address)
						if err != nil {
							continue
						}
						if !ip.IsLoopback() {
							agentIPs = append(agentIPs, ip.String())
						}
					}
				}
				
				// Check if another listener redirects to this listener
				found := false
				var checkAddresses []string
				
				if listenerHost == "0.0.0.0" || listenerHost == "" {
					// Wildcard - check all agent IPs
					for _, ip := range agentIPs {
						checkAddresses = append(checkAddresses, fmt.Sprintf("%s:%s", ip, listenerPort))
					}
				} else {
					checkAddresses = append(checkAddresses, fmt.Sprintf("%s:%s", listenerHost, listenerPort))
				}
				
				for _, addr := range checkAddresses {
					if visited[addr] {
						continue
					}
					visited[addr] = true
					
					if info, ok := redirectsTo[addr]; ok {
						logrus.Debugf("Found listener on %s redirecting to %s", info.agent.Name, addr)
						chain = append(chain, info)
						currentAgent = info.agent
						currentListener = info.listener
						found = true
						break
					}
				}
				
				if !found {
					break
				}
				
				if len(chain) > 10 {
					logrus.Warnf("Redirect chain too long, stopping search")
					break
				}
			}
			
			// The last element in chain is the direct parent (closest to the proxy)
			if len(chain) > 0 {
				directParent := chain[len(chain)-1]
				parentAgent = directParent.agent
				parentAgentID = directParent.agentID
				parentListener = directParent.listener
				
				logrus.Debugf("Traced redirect chain (%d hops), direct parent: %s", 
					len(chain), parentAgent.Name)
			}
		} else {
			// Fallback: try the old method walking from the connection port
			currentTarget := fmt.Sprintf("%s:%s", localHost, localPort)
			var chain []listenerInfo
			visited := make(map[string]bool)
			
			for {
				if visited[currentTarget] {
					logrus.Debugf("Cycle detected in redirect chain at %s", currentTarget)
					break
				}
				visited[currentTarget] = true
				
				// Look for a listener that redirects TO currentTarget
				if info, ok := redirectsTo[currentTarget]; ok {
					logrus.Debugf("Found listener on %s (port %s) redirecting to %s", 
						info.agent.Name, info.listener.ListenerAddr(), currentTarget)
					chain = append(chain, info)
					
					// Now find where THIS listener is located (on which IPs)
					// and continue walking backwards
					listenerHost, listenerPort, err := net.SplitHostPort(info.listener.ListenerAddr())
					if err != nil {
						break
					}
					
					// Get all IPs for this agent to find what might connect to this listener
					agentIPs := []string{}
					for _, ifaceInfo := range info.agent.Network {
						for _, address := range ifaceInfo.Addresses {
							ip, _, err := net.ParseCIDR(address)
							if err != nil {
								continue
							}
							if !ip.IsLoopback() {
								agentIPs = append(agentIPs, ip.String())
							}
						}
					}
					
					// Try each IP (the previous hop might connect to any of them)
					found := false
					if listenerHost == "0.0.0.0" || listenerHost == "" {
						// Wildcard listener - try all IPs
						for _, ip := range agentIPs {
							nextTarget := fmt.Sprintf("%s:%s", ip, listenerPort)
							// Check if something redirects to this address
							if _, ok := redirectsTo[nextTarget]; ok {
								currentTarget = nextTarget
								found = true
								logrus.Debugf("Walking back to %s", nextTarget)
								break
							}
						}
					} else {
						// Specific IP
						currentTarget = info.listener.ListenerAddr()
						found = true
					}
					
					if !found {
						// No more listeners redirect to this one
						break
					}
				} else {
					// No more listeners in chain
					logrus.Debugf("No listener found redirecting to %s", currentTarget)
					break
				}
				
				// Safety: prevent infinite loops
				if len(chain) > 10 {
					logrus.Warnf("Redirect chain too long, stopping search")
					break
				}
			}
			
			// The last element in chain is the direct parent (closest to the proxy)
			if len(chain) > 0 {
				directParent := chain[len(chain)-1]
				parentAgent = directParent.agent
				parentAgentID = directParent.agentID
				parentListener = directParent.listener
				
				logrus.Debugf("Traced redirect chain (%d hops), direct parent: %s", 
					len(chain), parentAgent.Name)
			}
		}
	}
	
	// Build pivot chain
	if parentAgent != nil {
		logrus.Infof("Pivot detected: %s connected through %s's listener %s", 
			agent.Name, parentAgent.Name, parentListener.ListenerAddr())
		
		// Inherit parent's chain
		agent.PivotChain = []controller.PivotHop{}
		if len(parentAgent.PivotChain) > 0 {
			agent.PivotChain = append(agent.PivotChain, parentAgent.PivotChain...)
		}
		
		// Add parent as new hop
		agent.PivotChain = append(agent.PivotChain, controller.PivotHop{
			AgentID:      parentAgentID,
			ListenerAddr: parentListener.ListenerAddr(),
		})
		
		// Build and log complete path
		chainParts := []string{"Proxy"}
		for _, hop := range agent.PivotChain {
			if hopAgent, ok := AgentList[hop.AgentID]; ok {
				chainParts = append(chainParts, hopAgent.Name)
			}
		}
		chainParts = append(chainParts, agent.Name)
		
		logrus.Infof("Pivot chain for %s: %d hops | Path: %s", 
			agent.Name, len(agent.PivotChain), strings.Join(chainParts, " ← "))
	} else {
		logrus.Debugf("No pivot detected for %s (direct connection)", agent.Name)
	}

	// Check for agent recovery
	for agentID, registeredAgents := range AgentList {
		if agent.SessionID == registeredAgents.SessionID {
			// Check if existing session is truly alive and functional
			sessionFunctional := false
			if registeredAgents.Session != nil {
				select {
				case <-registeredAgents.Session.CloseChan():
					logrus.Debugf("Existing session for %s is closed", agent.SessionID)
				default:
					if registeredAgents.Alive() {
						testStream, err := registeredAgents.Session.Open()
						if err != nil {
							logrus.Debugf("Session appears alive but cannot open stream: %v", err)
						} else {
							testStream.Close()
							sessionFunctional = true
						}
					}
				}
			}
			
			if sessionFunctional {
				logrus.Infof("Agent %s already connected, rejecting duplicate from %s", agent.SessionID, agent.Session.RemoteAddr())
				if agent.Session != nil {
					agent.Session.Close()
				}
				return fmt.Errorf("agent %s already connected", agent.SessionID)
			}
			
			// Session is dead, perform recovery
			logrus.Infof("Recovering agent: %s (ID: %d)", registeredAgents.Name, agentID)
			recovered = true
			
			if registeredAgents.Session != nil {
				registeredAgents.Session.Close()
			}
			
			registeredAgents.Session = agent.Session
			registeredAgents.PivotChain = agent.PivotChain

			savedInterface := registeredAgents.Interface
			tunnelWasRunning := registeredAgents.Running
			
			if savedInterface != "" {
				logrus.Infof("Restoring tunnel for agent %s on interface %s", registeredAgents.Name, savedInterface)

				if tunnelWasRunning {
					select {
					case registeredAgents.CloseChan <- true:
					default:
					}
					time.Sleep(500 * time.Millisecond)
				}

				registeredAgents.Running = false
				
				if netinfo.InterfaceExist(savedInterface) {
					logrus.Infof("Cleaning up stale interface %s...", savedInterface)
					stun, err := netinfo.GetTunByName(savedInterface)
					if err == nil {
						configState, err := config.GetInterfaceConfigState()
						if err == nil {
							if ifaceConfig, ok := configState[savedInterface]; ok {
								for _, ifcfg := range ifaceConfig.Routes {
									if ifcfg.Active {
										logrus.Debugf("Removing stale route %s", ifcfg.Destination)
										if err := stun.DelRoute(ifcfg.Destination); err != nil {
											logrus.Debugf("Route removal: %v", err)
										}
									}
								}
							}
						}
						logrus.Debugf("Destroying stale interface %s...", savedInterface)
						if err := stun.Destroy(); err != nil {
							logrus.Warnf("Could not destroy interface: %v", err)
						}
						time.Sleep(200 * time.Millisecond)
					}
				}
				
				logrus.Infof("Recreating interface %s...", savedInterface)
				if err := netinfo.CreateTUN(savedInterface); err != nil {
					logrus.Errorf("Could not recreate interface: %v", err)
					return fmt.Errorf("failed to recreate interface: %v", err)
				}

				if err := StartTunnel(registeredAgents, savedInterface); err != nil {
					logrus.Errorf("Failed to restore tunnel: %v", err)
					return fmt.Errorf("failed to restore tunnel: %v", err)
				}
			}

			var listenersToRestore []struct {
				listenerAddr string
				network      string
				redirectAddr string
			}

			for _, listener := range registeredAgents.Listeners {
				if listener != nil {
					logrus.Infof("Collecting listener info for restoration: %s", listener.String())
					listenersToRestore = append(listenersToRestore, struct {
						listenerAddr string
						network      string
						redirectAddr string
					}{
						listenerAddr: listener.ListenerAddr(),
						network:      listener.Network(),
						redirectAddr: listener.RedirectAddr(),
					})
					if err := listener.Stop(); err != nil {
						logrus.Warnf("Failed to stop old listener: %v", err)
					}
				}
			}

			registeredAgents.Listeners = []*proxy.LigoloListener{}

			if len(listenersToRestore) > 0 {
				time.Sleep(500 * time.Millisecond)
			}

			for _, listenerInfo := range listenersToRestore {
				logrus.Infof("Restoring listener: [%s] %s => %s", listenerInfo.network, listenerInfo.listenerAddr, listenerInfo.redirectAddr)
				
				proxyListener, err := registeredAgents.AddListener(listenerInfo.listenerAddr, listenerInfo.network, listenerInfo.redirectAddr)
				if err != nil {
					logrus.Errorf("Failed to restore listener: %v", err)
					continue
				}
				
				go func(l *proxy.LigoloListener, a *controller.LigoloAgent) {
					err := l.StartRelay()
					if err != nil {
						logrus.WithFields(logrus.Fields{"listener": l.String(), "agent": a.Name, "id": a.SessionID}).Warnf("Listener relay ended: %v", err)
					}
				}(proxyListener, registeredAgents)
				
				logrus.Infof("Listener restored successfully: %s", proxyListener.String())
			}
			return nil
		}
	}

	// New agent
	if !recovered {
		if config.Config.GetBool(fmt.Sprintf("agent.%s.autobind", agent.SessionID)) {
			autobindInterface := config.Config.GetString(fmt.Sprintf("agent.%s.interface", agent.SessionID))
			logrus.Infof("Starting autobind session: %s on interface %s", agent.SessionID, autobindInterface)
			if err := StartTunnel(agent, autobindInterface); err != nil {
				logrus.Error("unable to start tunnel for autobind: ", err)
			}
		}
	}
	
	AgentCounter++
	AgentList[AgentCounter] = agent
	return nil
}

func StartTunnel(agent *controller.LigoloAgent, tunName string) error {
	configState, err := config.GetInterfaceConfigState()
	if err != nil {
		return err
	}
	
	interfaceExists := netinfo.InterfaceExist(tunName)
	
	// Create interface if needed
	if _, ok := configState[tunName]; ok {
		if runtime.GOOS == "linux" && !interfaceExists {
			logrus.Debugf("Creating tun interface %s", tunName)
			if err := netinfo.CreateTUN(tunName); err != nil {
				return fmt.Errorf("failed to create TUN interface: %w", err)
			}
		}
	} else if !interfaceExists {
		logrus.Debugf("Creating tun interface %s (no prior config)", tunName)
		if err := netinfo.CreateTUN(tunName); err != nil {
			return fmt.Errorf("failed to create TUN interface: %w", err)
		}
	}

	logrus.Infof("Starting tunnel to %s (%s)", agent.Name, agent.SessionID)
	ligoloStack, err := proxy.NewLigoloTunnel(netstack.StackSettings{
		TunName:     tunName,
		MaxInflight: 4096,
	})
	if err != nil {
		return err
	}

	// Add routes
	if ifaceConfig, ok := configState[tunName]; ok {
		for _, ifcfg := range ifaceConfig.Routes {
			logrus.Debugf("Adding route %s on interface %s", ifcfg.Destination, tunName)
			tun, err := netinfo.GetTunByName(tunName)
			if err != nil {
				logrus.Warnf("Could not get TUN interface: %v", err)
				continue
			}
			if err := tun.AddRoute(ifcfg.Destination); err != nil {
				if strings.Contains(err.Error(), "file exists") || strings.Contains(err.Error(), "exists") {
					logrus.Debugf("Route %s already exists", ifcfg.Destination)
				} else {
					logrus.Warnf("Could not add route %s: %v", ifcfg.Destination, err)
				}
			}
		}
	}

	ifName, err := ligoloStack.GetStack().Interface().Name()
	if err != nil {
		logrus.Warn("unable to get interface name, err:", err)
		ifName = tunName
	}
	agent.Interface = ifName
	agent.Running = true

	ctx, cancelTunnel := context.WithCancel(context.Background())
	
	go ligoloStack.HandleSession(agent.Session, ctx)

	// Watchdog
	go func() {
		for {
			select {
			case <-agent.CloseChan:
				logrus.Infof("Closing tunnel to %s (%s)...", agent.Name, agent.SessionID)
				cancelTunnel()
				agent.Running = false
				
				// Clean up routes on user stop
				if netinfo.InterfaceExist(agent.Interface) {
					tun, err := netinfo.GetTunByName(agent.Interface)
					if err == nil {
						configState, err := config.GetInterfaceConfigState()
						if err == nil {
							if ifaceConfig, ok := configState[agent.Interface]; ok {
								for _, ifcfg := range ifaceConfig.Routes {
									logrus.Debugf("Removing route %s", ifcfg.Destination)
									tun.DelRoute(ifcfg.Destination)
								}
							}
						}
					}
				}
				return
				
			case <-agent.Session.CloseChan():
				logrus.Warnf("Lost tunnel connection with agent %s (%s)!", agent.Name, agent.SessionID)
				
				// FIXED: Properly clean up the old tunnel when agent drops
				agent.Running = false
				cancelTunnel()
				
				// CRITICAL FIX: Remove routes from the stale interface
				// These routes point to the old (now closed) TUN fd
				if netinfo.InterfaceExist(agent.Interface) {
					logrus.Infof("Cleaning up stale routes on %s after connection loss", agent.Interface)
					tun, err := netinfo.GetTunByName(agent.Interface)
					if err == nil {
						configState, err := config.GetInterfaceConfigState()
						if err == nil {
							if ifaceConfig, ok := configState[agent.Interface]; ok {
								for _, ifcfg := range ifaceConfig.Routes {
									logrus.Debugf("Removing stale route %s", ifcfg.Destination)
									if err := tun.DelRoute(ifcfg.Destination); err != nil {
										logrus.Debugf("Route removal: %v", err)
									}
								}
							}
						}
					}
					// Destroy the interface to release the stale fd
					logrus.Debugf("Destroying stale interface %s", agent.Interface)
					if err := tun.Destroy(); err != nil {
						logrus.Warnf("Could not destroy interface: %v", err)
					}
				}
				
				if currentAgent, ok := AgentList[CurrentAgentID]; ok {
					if currentAgent.SessionID == agent.SessionID {
						App.SetDefaultPrompt()
					}
				}

				logrus.Infof("Tunnel cleaned up, waiting for agent %s to reconnect...", agent.Name)
				return
			}
		}
	}()

	return nil
}

func Run() {
	// AgentList contains all the connected agents
	AgentList = make(map[int]*controller.LigoloAgent)

	// session
	App.AddCommand(&grumble.Command{
		Name:  "session",
		Help:  "Change the current relay agent",
		Usage: "session",
		Run: func(c *grumble.Context) error {
			AgentListMutex.Lock()
			sessionCount := 0
			for _, agent := range AgentList {
				if agent.Alive() {
					sessionCount += 1
				}
			}
			if sessionCount == 0 {
				AgentListMutex.Unlock()
				return errors.New("no sessions available")
			}
			AgentListMutex.Unlock()
			var session string
			sessionSelector := &survey.Select{
				Message: "Specify a session :",
				Options: func() (out []string) {
					AgentListMutex.Lock()
					for id, agent := range AgentList {
						if agent.Alive() {
							out = append(out, fmt.Sprintf("%d - %s", id, agent.String()))
						}
					}
					AgentListMutex.Unlock()
					return
				}(),
			}
			err := survey.AskOne(sessionSelector, &session)
			if err != nil {
				return err
			}

			s := strings.Split(session, " ")
			sessionID, err := strconv.Atoi(s[0])
			if err != nil {
				return err
			}

			CurrentAgentID = sessionID
			c.App.SetPrompt(fmt.Sprintf("[Agent : %s] » ", AgentList[CurrentAgentID].Name))
			return nil
		},
	})

	// certificate_fingerprint
	App.AddCommand(&grumble.Command{
		Name:  "certificate_fingerprint",
		Help:  "Show the current selfcert fingerprint",
		Usage: "certificate_fingerprint",
		Run: func(c *grumble.Context) error {
			selfcrt, err := ProxyController.GetSelfCertificateSignature()
			if err != nil {
				return err
			}
			if selfcrt == nil {
				return errors.New("certificate is nil")
			}
			logrus.Printf("TLS Certificate fingerprint for %s is: %X\n", ProxyController.CertManagerConfig.SelfcertDomain, sha256.Sum256(selfcrt.Certificate[0]))
			return nil
		},
	})

	// connect_agent
	App.AddCommand(&grumble.Command{
		Name:  "connect_agent",
		Help:  "Attempt to connect to a bind agent",
		Usage: "connect_agent --ip [agentip]",
		Flags: func(f *grumble.Flags) {
			f.StringL("ip", "", "The agent ip:port")
			f.BoolL("ignore-cert", false, "Ignore TLS certificate verification")
		},
		Run: func(c *grumble.Context) error {
			tlsConfig := &tls.Config{}
			tlsConfig.InsecureSkipVerify = true

			remoteConn, err := tls.Dial("tcp", c.Flags.String("ip"), tlsConfig)
			if err != nil {
				return err
			}
			if !c.Flags.Bool("ignore-cert") {
				cert := remoteConn.ConnectionState().PeerCertificates[0].Raw
				shaSum := sha256.Sum256(cert)
				confirmTLS := false
				prompt := &survey.Confirm{
					Message: fmt.Sprintf("TLS Certificate Fingerprint is: %X, connect?", shaSum),
				}
				survey.AskOne(prompt, &confirmTLS)
				if !confirmTLS {
					remoteConn.Close()
					return errors.New("connection aborted (user did not validate TLS cert)")
				}
			}

			yamuxConn, err := yamux.Client(remoteConn, nil)
			if err != nil {
				return err
			}

			agent, err := controller.NewAgent(yamuxConn)
			if err != nil {
				logrus.Errorf("could not register agent, error: %v", err)
				return err
			}

			logrus.WithFields(logrus.Fields{"remote": remoteConn.RemoteAddr(), "name": agent.Name, "id": agent.SessionID}).Info("Agent connected.")

			if err := RegisterAgent(agent); err != nil {
				logrus.Errorf("could not register agent: %s", err.Error())
			}
			return nil
		},
	})

	// tunnel_start
	App.AddCommand(&grumble.Command{
		Name:      "tunnel_start",
		Help:      "Start relaying connection to the current agent",
		Usage:     "tunnel_start --tun ligolo",
		HelpGroup: "Tunneling",
		Aliases:   []string{"start"},
		Flags: func(f *grumble.Flags) {
			f.StringL("tun", "ligolo", "the interface to run the proxy on")
		},
		Run: func(c *grumble.Context) error {
			if _, ok := AgentList[CurrentAgentID]; !ok {
				return ErrInvalidAgent
			}
			CurrentAgent := AgentList[CurrentAgentID]

			if CurrentAgent.Session == nil {
				return ErrInvalidAgent
			}

			if CurrentAgent.Running {
				return ErrAlreadyRunning
			}

			for _, agent := range AgentList {
				if agent.Running {
					if agent.Interface == c.Flags.String("tun") && agent.Alive() {
						return errors.New("a tunnel is already using this interface name. Please use a different name using the --tun option")
					}
				}
			}

			if err := StartTunnel(CurrentAgent, c.Flags.String("tun")); err != nil {
				return fmt.Errorf("unable to start tunnel: %s", err.Error())
			}
			return nil
		},
	})

	// tunnel_list
	App.AddCommand(&grumble.Command{
		Name:      "tunnel_list",
		Help:      "List active tunnels and sessions",
		Usage:     "tunnel_list",
		HelpGroup: "Tunneling",
		Aliases:   []string{"session_list"},
		Run: func(c *grumble.Context) error {
			t := table.NewWriter()
			t.SetStyle(table.StyleLight)
			t.SetTitle("Active sessions and tunnels")
			t.AppendHeader(table.Row{"#", "Agent", "Interface", "Pivot Chain", "Status"})

			AgentListMutex.Lock()
			for id, agent := range AgentList {
				var status string
				if agent.Alive() {
					status = text.Colors{text.FgGreen}.Sprintf("Online")
				} else {
					status = text.Colors{text.FgRed}.Sprintf("Offline (Awaiting recovery)")
				}
				
				// Build pivot chain display
				var pivotChainStr string
				if len(agent.PivotChain) == 0 {
					pivotChainStr = text.Colors{text.FgCyan}.Sprintf("Direct")
				} else {
					pivotChainStr = text.Colors{text.FgYellow}.Sprintf("%d hops", len(agent.PivotChain))
				}
				
				t.AppendRow(table.Row{id, agent.String(), agent.Interface, pivotChainStr, status})
			}
			AgentListMutex.Unlock()
			App.Println(t.Render())
			return nil
		},
	})

	// tunnel_stop
	App.AddCommand(&grumble.Command{
		Name:      "tunnel_stop",
		Help:      "Stop the tunnel",
		Usage:     "stop",
		HelpGroup: "Tunneling",
		Aliases:   []string{"stop"},
		Flags: func(f *grumble.Flags) {
			f.IntL("agent", -1, "The agent to stop")
		},
		Run: func(c *grumble.Context) error {
			var selectedAgent int
			if c.Flags.Int("agent") != -1 {
				selectedAgent = c.Flags.Int("agent")
			} else {
				selectedAgent = CurrentAgentID
			}
			if _, ok := AgentList[selectedAgent]; !ok {
				return ErrInvalidAgent
			}

			CurrentAgent := AgentList[selectedAgent]

			if CurrentAgent.Session == nil || !CurrentAgent.Running {
				return ErrNotRunning
			}
			CurrentAgent.CloseChan <- true
			CurrentAgent.Running = false
			return nil
		},
	})

	// ifconfig
	App.AddCommand(&grumble.Command{
		Name:  "ifconfig",
		Help:  "Show agent interfaces",
		Usage: "ifconfig",
		Run: func(c *grumble.Context) error {
			if _, ok := AgentList[CurrentAgentID]; !ok {
				return ErrInvalidAgent
			}
			CurrentAgent := AgentList[CurrentAgentID]
			// Note: Network information is not refreshed when calling this command
			if CurrentAgent.Session == nil {
				return ErrInvalidAgent
			}
			for n, ifaceInfo := range CurrentAgent.Network {
				t := table.NewWriter()
				t.SetStyle(table.StyleLight)
				t.SetTitle(fmt.Sprintf("Interface %d", n))

				t.AppendRow(table.Row{"Name", ifaceInfo.Name})
				t.AppendRow(table.Row{"Hardware MAC", ifaceInfo.HardwareAddr})
				t.AppendRow(table.Row{"MTU", ifaceInfo.MTU})
				t.AppendRow(table.Row{"Flags", ifaceInfo.Flags})

				for _, address := range ifaceInfo.Addresses {
					if address != "" {
						ip, _, err := net.ParseCIDR(address)
						if err != nil {
							continue
						}
						if ip.To4() != nil {
							t.AppendRow(table.Row{"IPv4 Address", address})
						} else {
							t.AppendRow(table.Row{"IPv6 Address", address})
						}
					}
				}
				App.Println(t.Render())
			}
			return nil
		},
	})

	// listener_list
	App.AddCommand(&grumble.Command{
		Name:      "listener_list",
		Help:      "List currently running listeners",
		Usage:     "listener_list",
		HelpGroup: "Listeners",
		Run: func(c *grumble.Context) error {
			t := table.NewWriter()
			t.SetStyle(table.StyleLight)
			t.SetTitle("Active listeners")
			t.AppendHeader(table.Row{"#", "Agent", "Network", "Agent listener address", "Proxy redirect address", "Status"})

			for _, agent := range AgentList {
				for _, listener := range agent.Listeners {
					var status string
					if agent.Alive() {
						status = text.Colors{text.FgGreen}.Sprintf("Online")
					} else {
						status = text.Colors{text.FgRed}.Sprintf("Offline")
					}
					t.AppendRow(table.Row{listener.ID, agent.String(), listener.Network(), listener.ListenerAddr(), listener.RedirectAddr(), status})
				}
			}

			c.App.Println(t.Render())
			return nil
		},
	})

	// listener_stop
	App.AddCommand(&grumble.Command{
		Name:      "listener_stop",
		Help:      "Stop a listener",
		Usage:     "listener_stop",
		HelpGroup: "Listeners",
		Run: func(c *grumble.Context) error {
			var session string
			type LigoloListenerAgent struct {
				listener *proxy.LigoloListener
				agent    *controller.LigoloAgent
			}
			listenerMap := make(map[int]LigoloListenerAgent)
			listenerSelector := &survey.Select{
				Message: "Specify the listener to stop:",
				Options: func() (out []string) {
					AgentListMutex.Lock()
					i := 0
					for _, agent := range AgentList {
						for _, listener := range agent.Listeners {
							if listener != nil {
								var status string
								if agent.Alive() {
									status = text.Colors{text.FgGreen}.Sprintf("Online")
								} else {
									status = text.Colors{text.FgRed}.Sprintf("Offline")
								}
								out = append(out, fmt.Sprintf("%d - Agent: %s - Net: %s - Agent Listener: %s - Redirect: %s [%s]", i, agent.String(), listener.Network(), listener.ListenerAddr(), listener.RedirectAddr(), status))
								listenerMap[i] = LigoloListenerAgent{listener: listener, agent: agent}
								i++
							}
						}
					}
					AgentListMutex.Unlock()
					return
				}(),
			}

			err := survey.AskOne(listenerSelector, &session)
			if err != nil {
				return err
			}

			s := strings.Split(session, " ")
			selectionIndex, err := strconv.Atoi(s[0])
			if err != nil {
				return err
			}

			if listenerInfo, ok := listenerMap[selectionIndex]; ok {
				// Stop the listener
				if err := listenerInfo.listener.Stop(); err != nil {
					return err
				}
				// Delete from agent's slice using listener.ID (which is the slice index)
				listenerInfo.agent.DeleteListener(int(listenerInfo.listener.ID))
				logrus.Infof("Listener stopped: %s", listenerInfo.listener.String())
			} else {
				return errors.New("invalid listener id")
			}
			return nil
		},
	})

	// listener_add
	App.AddCommand(&grumble.Command{
		Name:      "listener_add",
		Help:      "Listen on the agent and redirect connections to the desired address",
		Usage:     "listener_add --addr [agent_listening_address:port] --to [local_listening_address:port] --tcp/--udp",
		HelpGroup: "Listeners",
		Flags: func(f *grumble.Flags) {
			f.BoolL("tcp", false, "Use TCP listener")
			f.BoolL("udp", false, "Use UDP listener")
			f.StringL("addr", "", "The agent listening address:port")
			f.StringL("to", "", "Where to redirect connections")
		},
		Run: func(c *grumble.Context) error {
			if _, ok := AgentList[CurrentAgentID]; !ok {
				return ErrInvalidAgent
			}
			CurrentAgent := AgentList[CurrentAgentID]
			if CurrentAgent.Session == nil {
				return errors.New("please, select an agent using the session command")
			}
			var netProto string

			if c.Flags.Bool("tcp") && c.Flags.Bool("udp") {
				return errors.New("choose TCP or UDP, not both")
			}
			if c.Flags.Bool("tcp") {
				netProto = "tcp"
			}
			if c.Flags.Bool("udp") {
				netProto = "udp"
			}
			if netProto == "" {
				netProto = "tcp" // Use TCP by default.
			}

			if c.Flags.String("to") == "" {
				return errors.New("please, specify a valid redirect (to) IP address - expected format : ip:port")
			}

			// Check if specified IP is valid.
			if _, _, err := net.SplitHostPort(c.Flags.String("to")); err != nil {
				return err
			}
			if _, _, err := net.SplitHostPort(c.Flags.String("addr")); err != nil {
				return err
			}

			proxyListener, err := CurrentAgent.AddListener(c.Flags.String("addr"), netProto, c.Flags.String("to"))
			if err != nil {
				return err
			}

			logrus.Infof("Listener %d created on remote agent!", proxyListener.ID)

			go func() {
				err := proxyListener.StartRelay()
				if err != nil {
					// FIXED: Log relay errors as warnings to prevent cascade failures
					// This is critical for double-pivot scenarios (e.g., DC01 -> DMZ01 -> Proxy)
					logrus.WithFields(logrus.Fields{"listener": proxyListener.String(), "agent": CurrentAgent.Name, "id": CurrentAgent.SessionID}).Warnf("Listener relay ended: %v", err)
					return
				}

				logrus.WithFields(logrus.Fields{"listener": proxyListener.String(), "agent": CurrentAgent.Name, "id": CurrentAgent.SessionID}).Info("Listener ended without error")
				return
			}()

			return nil
		},
	})

	// backhome
	App.AddCommand(&grumble.Command{
		Name:      "backhome",
		Help:      "Create a reverse path through pivot chain back to proxy/attacker",
		Usage:     "backhome --to [proxy|<local_port>] [--port <remote_port_to_open>] [--tcp|--udp]",
		HelpGroup: "Listeners",
		Flags: func(f *grumble.Flags) {
			f.StringL("to", "proxy", "Destination: 'proxy' or specific port number on attacker host")
			f.IntL("port", 0, "Port to open on the remote agent (auto-assigned if not specified)")
			f.BoolL("tcp", false, "Use TCP listener (default)")
			f.BoolL("udp", false, "Use UDP listener")
		},
		Run: func(c *grumble.Context) error {
			if _, ok := AgentList[CurrentAgentID]; !ok {
				return ErrInvalidAgent
			}
			CurrentAgent := AgentList[CurrentAgentID]
			if CurrentAgent.Session == nil {
				return errors.New("please select an agent using the session command")
			}

			// Determine protocol
			var netProto string
			if c.Flags.Bool("tcp") && c.Flags.Bool("udp") {
				return errors.New("choose TCP or UDP, not both")
			}
			if c.Flags.Bool("udp") {
				netProto = "udp"
			} else {
				netProto = "tcp" // Default to TCP
			}

			// Check if this agent has a pivot chain, if not, act as a simple listener_add
			if len(CurrentAgent.PivotChain) == 0 {
				// Determine the port to open on the agent
				remotePort := c.Flags.Int("port")
				if remotePort == 0 {
					remotePort = findAvailablePort(CurrentAgent, 0)
					logrus.Debugf("Auto-assigned port %d on agent", remotePort)
				}
				
				// Determine target destination
				toFlag := c.Flags.String("to")
				var finalDestination string
				
				if toFlag == "proxy" {
					proxyHost, proxyPort, err := net.SplitHostPort(CurrentAgent.Session.LocalAddr().String())
					if err != nil {
						return fmt.Errorf("failed to determine proxy address: %v", err)
					}
					finalDestination = fmt.Sprintf("%s:%s", proxyHost, proxyPort)
				} else {
					proxyHost, _, err := net.SplitHostPort(CurrentAgent.Session.LocalAddr().String())
					if err != nil {
						return fmt.Errorf("failed to determine proxy address: %v", err)
					}
					finalDestination = fmt.Sprintf("%s:%s", proxyHost, toFlag)
				}
				
				// Create the listener
				listenAddr := fmt.Sprintf("0.0.0.0:%d", remotePort)
				proxyListener, err := CurrentAgent.AddListener(listenAddr, netProto, finalDestination)
				if err != nil {
					return fmt.Errorf("failed to create listener: %v", err)
				}
				
				go func(l *proxy.LigoloListener, a *controller.LigoloAgent) {
					err := l.StartRelay()
					if err != nil {
						logrus.WithFields(logrus.Fields{
							"listener": l.String(), 
							"agent":    a.Name, 
							"id":       a.SessionID,
						}).Warnf("Backhome listener relay ended: %v", err)
					}
				}(proxyListener, CurrentAgent)
				
				// Show available NICs with their IPs
				var targetIPs []string
				for _, ifaceInfo := range CurrentAgent.Network {
					for _, address := range ifaceInfo.Addresses {
						ip, _, err := net.ParseCIDR(address)
						if err != nil {
							continue
						}
						if !ip.IsLoopback() && ip.To4() != nil {
							targetIPs = append(targetIPs, fmt.Sprintf("%s:%d", ip.String(), remotePort))
						}
					}
				}
				
				protoStr := text.Colors{text.FgBlue}.Sprintf("[%s]", strings.ToUpper(netProto))
				targetsStr := text.Colors{text.FgCyan}.Sprint(strings.Join(targetIPs, " | "))
				destStr := text.Colors{text.FgMagenta}.Sprint(finalDestination)
				agentStr := text.Colors{text.FgGreen}.Sprint(CurrentAgent.Name)
				portStr := text.Colors{text.FgYellow}.Sprintf(":%d", remotePort)
				
				logrus.Info(text.Colors{text.FgGreen}.Sprintf("✓ Direct backhome %s: %s%s → %s", protoStr, agentStr, portStr, destStr))
				logrus.Infof("  Connect to: %s", targetsStr)
				
				return nil
			}

			// Determine target destination
			toFlag := c.Flags.String("to")
			var finalDestination string
			
			if toFlag == "proxy" {
				firstHop := CurrentAgent.PivotChain[0]
				firstAgent, ok := AgentList[firstHop.AgentID]
				if !ok {
					return fmt.Errorf("first pivot agent (ID: %d) not found", firstHop.AgentID)
				}
				
				proxyHost, proxyPort, err := net.SplitHostPort(firstAgent.Session.LocalAddr().String())
				if err != nil {
					return fmt.Errorf("failed to determine proxy address: %v", err)
				}
				finalDestination = fmt.Sprintf("%s:%s", proxyHost, proxyPort)
			} else {
				firstHop := CurrentAgent.PivotChain[0]
				firstAgent, ok := AgentList[firstHop.AgentID]
				if !ok {
					return fmt.Errorf("first pivot agent (ID: %d) not found", firstHop.AgentID)
				}
				
				proxyHost, _, err := net.SplitHostPort(firstAgent.Session.LocalAddr().String())
				if err != nil {
					return fmt.Errorf("failed to determine proxy address: %v", err)
				}
				finalDestination = fmt.Sprintf("%s:%s", proxyHost, toFlag)
			}

			// Determine the port to open on the target agent
			remotePort := c.Flags.Int("port")
			if remotePort == 0 {
				remotePort = findAvailablePort(CurrentAgent, 0)
				logrus.Debugf("Auto-assigned port %d on target agent", remotePort)
			}

			// Build the reverse chain
			currentDestination := finalDestination
			var createdListeners []struct {
				agentID    int
				listenerID int32
				port       int
			}

			// Start from the end of the pivot chain and work backwards
			for i := len(CurrentAgent.PivotChain) - 1; i >= 0; i-- {
				hop := CurrentAgent.PivotChain[i]
				intermediateAgent, ok := AgentList[hop.AgentID]
				if !ok {
					for _, listener := range createdListeners {
						if agent, ok := AgentList[listener.agentID]; ok {
							agent.DeleteListener(int(listener.listenerID))
						}
					}
					return fmt.Errorf("intermediate agent %d not found in pivot chain", hop.AgentID)
				}

				if !intermediateAgent.Alive() {
					for _, listener := range createdListeners {
						if agent, ok := AgentList[listener.agentID]; ok {
							agent.DeleteListener(int(listener.listenerID))
						}
					}
					return fmt.Errorf("intermediate agent %s (ID: %d) is offline", intermediateAgent.Name, hop.AgentID)
				}

				// Use smart port allocation - find an available ephemeral port
				listenPort := findAvailablePort(intermediateAgent, 0)
				listenAddr := fmt.Sprintf("0.0.0.0:%d", listenPort)

				logrus.Debugf("Creating intermediate listener on %s: %s -> %s (%s)", 
					intermediateAgent.Name, listenAddr, currentDestination, netProto)

				proxyListener, err := intermediateAgent.AddListener(listenAddr, netProto, currentDestination)
				if err != nil {
					for _, listener := range createdListeners {
						if agent, ok := AgentList[listener.agentID]; ok {
							agent.DeleteListener(int(listener.listenerID))
						}
					}
					return fmt.Errorf("failed to create listener on %s: %v", intermediateAgent.Name, err)
				}

				createdListeners = append(createdListeners, struct {
					agentID    int
					listenerID int32
					port       int
				}{hop.AgentID, proxyListener.ID, listenPort})

				go func(l *proxy.LigoloListener, a *controller.LigoloAgent) {
					err := l.StartRelay()
					if err != nil {
						logrus.WithFields(logrus.Fields{
							"listener": l.String(), 
							"agent":    a.Name, 
							"id":       a.SessionID,
						}).Warnf("Backhome listener relay ended: %v", err)
					}
				}(proxyListener, intermediateAgent)

				// Find the IP to use for the next hop
				var nextHopIP string
				for _, ifaceInfo := range intermediateAgent.Network {
					for _, address := range ifaceInfo.Addresses {
						ip, _, err := net.ParseCIDR(address)
						if err != nil {
							continue
						}
						if !ip.IsLoopback() && ip.To4() != nil {
							nextHopIP = ip.String()
							break
						}
					}
					if nextHopIP != "" {
						break
					}
				}

				if nextHopIP == "" {
					host, _, err := net.SplitHostPort(intermediateAgent.Session.RemoteAddr().String())
					if err == nil {
						nextHopIP = host
					} else {
						nextHopIP = "127.0.0.1"
						logrus.Warnf("Could not determine IP for %s, using localhost", intermediateAgent.Name)
					}
				}

				currentDestination = fmt.Sprintf("%s:%d", nextHopIP, listenPort)
			}

			// Finally, create a listener on the target agent
			targetListenAddr := fmt.Sprintf("0.0.0.0:%d", remotePort)

			logrus.Debugf("Creating final listener on %s: %s -> %s (%s)", 
				CurrentAgent.Name, targetListenAddr, currentDestination, netProto)

			proxyListener, err := CurrentAgent.AddListener(targetListenAddr, netProto, currentDestination)
			if err != nil {
				for _, listener := range createdListeners {
					if agent, ok := AgentList[listener.agentID]; ok {
						agent.DeleteListener(int(listener.listenerID))
					}
				}
				return fmt.Errorf("failed to create listener on target agent: %v", err)
			}

			go func(l *proxy.LigoloListener, a *controller.LigoloAgent) {
				err := l.StartRelay()
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"listener": l.String(), 
						"agent":    a.Name, 
						"id":       a.SessionID,
					}).Warnf("Backhome listener relay ended: %v", err)
				}
			}(proxyListener, CurrentAgent)

			// Show available NICs with their IPs
			var targetIPs []string
			for _, ifaceInfo := range CurrentAgent.Network {
				for _, address := range ifaceInfo.Addresses {
					ip, _, err := net.ParseCIDR(address)
					if err != nil {
						continue
					}
					if !ip.IsLoopback() && ip.To4() != nil {
						targetIPs = append(targetIPs, fmt.Sprintf("%s:%d", ip.String(), remotePort))
					}
				}
			}
			
			// Build compact chain visualization with ports
			var chainParts []string
			chainParts = append(chainParts, text.Colors{text.FgGreen}.Sprintf("%s:%d", CurrentAgent.Name, remotePort))
			
			for i := len(CurrentAgent.PivotChain) - 1; i >= 0; i-- {
				hop := CurrentAgent.PivotChain[i]
				if agent, ok := AgentList[hop.AgentID]; ok {
					// Find the port for this hop
					hopPort := 0
					for _, listener := range createdListeners {
						if listener.agentID == hop.AgentID {
							hopPort = listener.port
							break
						}
					}
					if hopPort > 0 {
						chainParts = append(chainParts, text.Colors{text.FgYellow}.Sprintf("%s:%d", agent.Name, hopPort))
					} else {
						chainParts = append(chainParts, text.Colors{text.FgYellow}.Sprint(agent.Name))
					}
				}
			}
			chainParts = append(chainParts, text.Colors{text.FgMagenta}.Sprint(finalDestination))
			
			protoStr := text.Colors{text.FgBlue}.Sprintf("[%s]", strings.ToUpper(netProto))
			targetsStr := text.Colors{text.FgCyan}.Sprint(strings.Join(targetIPs, " | "))
			chainStr := strings.Join(chainParts, " → ")
			
			logrus.Info(text.Colors{text.FgGreen}.Sprintf("✓ Backhome %s (%d hops): %s", protoStr, len(CurrentAgent.PivotChain), chainStr))
			logrus.Infof("  Connect to: %s", targetsStr)

			return nil
		},
	})

	//kill
	App.AddCommand(&grumble.Command{
		Name:    "kill",
		Help:    "Kill the current agent",
		Usage:   "kill",
		Aliases: []string{"agent_kill", "session_kill"},
		Run: func(c *grumble.Context) error {
			if _, ok := AgentList[CurrentAgentID]; !ok {
				return ErrInvalidAgent
			}
			currentAgent := AgentList[CurrentAgentID]
			if ask("Are you sure to kill the current agent?") {
				return currentAgent.Kill()
			}
			return nil
		},
	})

	// pivot_show
	App.AddCommand(&grumble.Command{
		Name:      "pivot_show",
		Help:      "Show detailed pivot chain for the current agent",
		Usage:     "pivot_show",
		HelpGroup: "Tunneling",
		Aliases:   []string{"show_pivot"},
		Run: func(c *grumble.Context) error {
			if _, ok := AgentList[CurrentAgentID]; !ok {
				return ErrInvalidAgent
			}
			CurrentAgent := AgentList[CurrentAgentID]
			if CurrentAgent.Session == nil {
				return ErrInvalidAgent
			}

			if len(CurrentAgent.PivotChain) == 0 {
				logrus.Info(text.Colors{text.FgCyan}.Sprint("Direct connection to proxy (no pivot chain)"))
				return nil
			}

			chainParts := []string{text.Colors{text.FgMagenta}.Sprint("Proxy")}
			
			for _, hop := range CurrentAgent.PivotChain {
				if agent, ok := AgentList[hop.AgentID]; ok {
					chainParts = append(chainParts, text.Colors{text.FgYellow}.Sprint(agent.Name))
				} else {
					chainParts = append(chainParts, text.Colors{text.FgRed}.Sprintf("Agent#%d[OFFLINE]", hop.AgentID))
				}
			}
			
			chainParts = append(chainParts, text.Colors{text.FgGreen}.Sprintf("%s (YOU)", CurrentAgent.Name))
			
			chainStr := strings.Join(chainParts, " ← ")
			
			logrus.Info(text.Colors{text.FgCyan}.Sprintf("Pivot chain (%d hops): %s", len(CurrentAgent.PivotChain), chainStr))

			return nil
		},
	})

}

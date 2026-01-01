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
	"crypto/rand"
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

func genRandomUUID() string {
	b := make([]byte, 8)
	_, err := rand.Read(b)
	if err != nil {
		logrus.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func RegisterAgent(agent *controller.LigoloAgent) error {
	AgentListMutex.Lock()
	defer AgentListMutex.Unlock()
	var recovered bool

	for agentID, registeredAgents := range AgentList {
		if agent.SessionID == registeredAgents.SessionID {
			// Check if existing session is truly alive and functional
			sessionFunctional := false
			if registeredAgents.Session != nil {
				select {
				case <-registeredAgents.Session.CloseChan():
					// Session is closed
					logrus.Debugf("Existing session for %s is closed", agent.SessionID)
				default:
					// Session channel is not closed, verify it's actually working
					if registeredAgents.Alive() {
						// Try to open a test stream to verify functionality
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
				// Session is truly alive and working, reject duplicate
				logrus.Infof("Agent %s already connected, rejecting duplicate from %s", 
					agent.SessionID, agent.Session.RemoteAddr())
				
				// Close the duplicate connection gracefully
				if agent.Session != nil {
					agent.Session.Close()
				}
				
				return fmt.Errorf("agent %s already connected", agent.SessionID)
			}
			
			// Session is dead or non-functional, perform recovery
			logrus.Infof("Recovering agent: %s (ID: %d)", registeredAgents.Name, agentID)
			recovered = true
			
			// Close old session if it exists
			if registeredAgents.Session != nil {
				registeredAgents.Session.Close()
			}
			
			// Update to new session
			registeredAgents.Session = agent.Session

			// FIXED: Check if tunnel was running and clean up properly
			savedInterface := registeredAgents.Interface
			tunnelWasRunning := registeredAgents.Running
			
			// ALWAYS restore tunnel if an interface was previously configured
			if savedInterface != "" {
				logrus.Infof("Restoring tunnel for agent %s on interface %s", registeredAgents.Name, savedInterface)

				// Stop the old tunnel if somehow still running
				if tunnelWasRunning {
					select {
					case registeredAgents.CloseChan <- true:
					default:
					}
					
					// Wait for cleanup
					time.Sleep(500 * time.Millisecond)
				}

				// Reset running flag
				registeredAgents.Running = false
				
				// CRITICAL: Clean up any stale interface state
				if netinfo.InterfaceExist(savedInterface) {
					logrus.Infof("Cleaning up stale interface %s...", savedInterface)
					stun, err := netinfo.GetTunByName(savedInterface)
					if err == nil {
						// Get current routes from config
						configState, err := config.GetInterfaceConfigState()
						if err == nil {
							if ifaceConfig, ok := configState[savedInterface]; ok {
								// Delete existing routes
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
						
						// Destroy interface to release old fd
						logrus.Debugf("Destroying stale interface %s...", savedInterface)
						if err := stun.Destroy(); err != nil {
							logrus.Warnf("Could not destroy interface: %v", err)
						}
						
						time.Sleep(200 * time.Millisecond)
					}
				}
				
				// Recreate interface with fresh fd
				logrus.Infof("Recreating interface %s...", savedInterface)
				if err := netinfo.CreateTUN(savedInterface); err != nil {
					logrus.Errorf("Could not recreate interface: %v", err)
					return fmt.Errorf("failed to recreate interface: %v", err)
				}

				// Start fresh tunnel on the SAME interface
				if err := StartTunnel(registeredAgents, savedInterface); err != nil {
					logrus.Errorf("Failed to restore tunnel: %v", err)
					return fmt.Errorf("failed to restore tunnel: %v", err)
				}
			}

			// FIXED: Properly restore listeners by recreating them
			var listenersToRestore []struct {
				listenerAddr string
				network      string
				redirectAddr string
			}

			// First, collect listener info and stop old listeners
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
					
					// Stop the old listener (this will close the proxy-side resources)
					if err := listener.Stop(); err != nil {
						logrus.Warnf("Failed to stop old listener: %v", err)
					}
				}
			}

			// Clear the old listeners array
			registeredAgents.Listeners = []*proxy.LigoloListener{}

			// Give agent time to clean up old port bindings
			if len(listenersToRestore) > 0 {
				time.Sleep(500 * time.Millisecond)
			}

			// Now recreate listeners on the agent side with the new session
			for _, listenerInfo := range listenersToRestore {
				logrus.Infof("Restoring listener: [%s] %s => %s", 
					listenerInfo.network, 
					listenerInfo.listenerAddr, 
					listenerInfo.redirectAddr)
				
				// AddListener will create a new listener on the agent side
				proxyListener, err := registeredAgents.AddListener(
					listenerInfo.listenerAddr,
					listenerInfo.network,
					listenerInfo.redirectAddr,
				)
				if err != nil {
					logrus.Errorf("Failed to restore listener: %v", err)
					continue
				}
				
				// Start the relay for the new listener
				go func(l *proxy.LigoloListener, a *controller.LigoloAgent) {
					err := l.StartRelay()
					if err != nil {
						logrus.WithFields(logrus.Fields{
							"listener": l.String(),
							"agent":    a.Name,
							"id":       a.SessionID,
						}).Warnf("Listener relay ended: %v", err)
					}
				}(proxyListener, registeredAgents)
				
				logrus.Infof("Listener restored successfully: %s", proxyListener.String())
			}
			
			return nil
		}
	}

	// New agent, not recovered
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

	App.AddCommand(&grumble.Command{Name: "tunnel_list",
		Help:      "List active tunnels and sessions",
		Usage:     "tunnel_list",
		HelpGroup: "Tunneling",
		Aliases:   []string{"session_list"},
		Run: func(c *grumble.Context) error {
			t := table.NewWriter()
			t.SetStyle(table.StyleLight)
			t.SetTitle("Active sessions and tunnels")
			t.AppendHeader(table.Row{"#", "Agent", "Interface", "Status"})

			AgentListMutex.Lock()

			for id, agent := range AgentList {
				var status string
				if agent.Alive() {
					status = text.Colors{text.FgGreen}.Sprintf("Online")
				} else {
					status = text.Colors{text.FgRed}.Sprintf("Offline (Awaiting recovery)")
				}
				t.AppendRow(table.Row{id, agent.String(), agent.Interface, status})

			}
			AgentListMutex.Unlock()
			App.Println(t.Render())

			return nil
		},
	})

	App.AddCommand(&grumble.Command{Name: "tunnel_stop",
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
								listenerMap[i] = LigoloListenerAgent{
									listener: listener,
									agent:    agent,
								}
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
					logrus.WithFields(logrus.Fields{
						"listener": proxyListener.String(),
						"agent":    CurrentAgent.Name,
						"id":       CurrentAgent.SessionID,
					}).Warnf("Listener relay ended: %v", err)
					return
				}

				logrus.WithFields(logrus.Fields{
					"listener": proxyListener.String(),
					"agent":    CurrentAgent.Name,
					"id":       CurrentAgent.SessionID,
				}).Info("Listener ended without error")
				return
			}()

			return nil
		},
	})

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
}

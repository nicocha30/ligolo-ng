package app

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

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

func RegisterAgent(agent *controller.LigoloAgent) error {
	AgentListMutex.Lock()
	defer AgentListMutex.Unlock()

	for _, registeredAgents := range AgentList {
		if agent.SessionID == registeredAgents.SessionID {
			logrus.Infof("Recovered an agent: %s", registeredAgents.Name)
			registeredAgents.Session = agent.Session
			if registeredAgents.Running {
				go StartTunnel(registeredAgents, registeredAgents.Interface)
			}

			for lid, listener := range registeredAgents.Listeners {
				logrus.Info(fmt.Sprintf("Restarting listener: %s", listener.String()))
				if err := listener.ResetMultiplexer(registeredAgents.Session); err != nil {
					logrus.Errorf("Failed to reset yamux: %v", err)
				}
				if err := listener.Stop(); err != nil {
					logrus.Error(err)
				}

				lis, err := proxy.NewListener(registeredAgents.Session, listener.ListenerAddr(), listener.Network(), listener.RedirectAddr())
				if err != nil {
					logrus.Error(err)
				}
				registeredAgents.Listeners[lid] = &lis
				go func() {
					err := lis.StartRelay()
					if err != nil {
						logrus.WithFields(logrus.Fields{"listener": lis.String(), "agent": agent.Name, "id": agent.SessionID}).Error("Listener relay failed with error: ", err)
						return
					}

					logrus.WithFields(logrus.Fields{"listener": lis.String(), "agent": agent.Name, "id": agent.SessionID}).Warning("Listener ended without error.")
					return
				}()
			}
			return nil
		}
	}
	AgentCounter++
	AgentList[AgentCounter] = agent
	return nil
}

func StartTunnel(agent *controller.LigoloAgent, tunName string) {
	logrus.Infof("Starting tunnel to %s (%s)", agent.Name, agent.SessionID)
	ligoloStack, err := proxy.NewLigoloTunnel(netstack.StackSettings{
		TunName:     tunName,
		MaxInflight: 4096,
	})
	if err != nil {
		logrus.Error("Unable to create tunnel, err:", err)
		return
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

	for {
		select {
		case <-agent.CloseChan: // User stopped
			logrus.Infof("Closing tunnel to %s (%s)...", agent.Name, agent.SessionID)
			cancelTunnel()
			return
		case <-agent.Session.CloseChan(): // Agent closed
			logrus.Warnf("Lost tunnel connection with agent %s (%s)!", agent.Name, agent.SessionID)
			//agent.Running = false
			//agent.Session = nil

			if currentAgent, ok := AgentList[CurrentAgentID]; ok {
				if currentAgent.SessionID == agent.SessionID {
					App.SetDefaultPrompt()
					agent.Session = nil
				}
			}

			cancelTunnel()
			return
		}
	}
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
				if agent.Session != nil && !agent.Session.IsClosed() {
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
						if agent.Session != nil && !agent.Session.IsClosed() {
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
			selfcrt := ProxyController.SelfCert
			if selfcrt == nil {
				return errors.New("certificate is nil")
			}
			logrus.Printf("TLS Certificate fingerprint for %s is: %X\n", ProxyController.SelfcertDomain, sha256.Sum256(selfcrt.Certificate[0]))

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
					if agent.Interface == c.Flags.String("tun") {
						return errors.New("a tunnel is already using this interface name. Please use a different name using the --tun option")
					}
				}
			}

			go StartTunnel(CurrentAgent, c.Flags.String("tun"))

			return nil
		},
	})

	App.AddCommand(&grumble.Command{Name: "tunnel_list",
		Help:      "List active tunnels",
		Usage:     "tunnel_list",
		HelpGroup: "Tunneling",
		Run: func(c *grumble.Context) error {
			t := table.NewWriter()
			t.SetStyle(table.StyleLight)
			t.SetTitle("Active tunnels")
			t.AppendHeader(table.Row{"#", "Agent", "Interface"})

			AgentListMutex.Lock()

			for id, agent := range AgentList {

				if agent.Running {
					t.AppendRow(table.Row{id, agent.Name, agent.Interface})
				}
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
					status := text.Colors{text.FgGreen}.Sprintf("Online")
					if agent.Session == nil || agent.Session.IsClosed() {
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
							status := text.Colors{text.FgGreen}.Sprintf("Online")
							if agent.Session == nil || agent.Session.IsClosed() {
								status = text.Colors{text.FgRed}.Sprintf("Offline")
							}
							out = append(out, fmt.Sprintf("%d - Agent: %s - Net: %s - Agent Listener: %s - Redirect: %s [%s]", i, agent.String(), listener.Network(), listener.ListenerAddr(), listener.RedirectAddr(), status))
							listenerMap[i] = LigoloListenerAgent{listener: listener, agent: agent}
							i++
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
			listenerId, err := strconv.Atoi(s[0])
			if err != nil {
				return err
			}

			if listener, ok := listenerMap[listenerId]; ok {
				if err := listener.listener.Stop(); err != nil {
					return err
				}
				listener.agent.DeleteListener(int(listener.listener.ID))
			} else {
				return errors.New("invalid listener id")
			}

			return nil
		},
	})

	App.AddCommand(&grumble.Command{
		Name:      "listener_add",
		Help:      "Listen on the agent and redirect connections to the desired address",
		Usage:     "listener_add --addr [agent_listening_address:port] --to [local_listening_address:port] --tcp/--udp (--no-retry)",
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
					logrus.WithFields(logrus.Fields{"listener": proxyListener.String(), "agent": CurrentAgent.Name, "id": CurrentAgent.SessionID}).Error("Listener relay failed with error: ", err)
					return
				}

				logrus.WithFields(logrus.Fields{"listener": proxyListener.String(), "agent": CurrentAgent.Name, "id": CurrentAgent.SessionID}).Warning("Listener ended without error.")
				return
			}()

			return nil
		},
	})
}

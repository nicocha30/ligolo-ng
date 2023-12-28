package app

import (
	"context"
	"errors"
	"fmt"
	"github.com/AlecAivazis/survey/v2"
	"github.com/desertbit/grumble"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/nicocha30/ligolo-ng/pkg/controller"
	"github.com/nicocha30/ligolo-ng/pkg/proxy"
	"github.com/nicocha30/ligolo-ng/pkg/proxy/netstack"
	"github.com/sirupsen/logrus"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

var AgentList map[int]*controller.LigoloAgent
var AgentListMutex sync.Mutex
var ListenerList map[int]controller.Listener
var ListenerListMutex sync.Mutex

var (
	ErrInvalidAgent   = errors.New("please, select an agent using the session command")
	ErrAlreadyRunning = errors.New("already running")
	ErrNotRunning     = errors.New("no tunnel started")
)

func RegisterAgent(agent *controller.LigoloAgent) error {
	AgentListMutex.Lock()
	AgentList[agent.Id] = agent
	AgentListMutex.Unlock()
	return nil
}

func Run() {
	// CurrentAgent points to the selected agent in the UI (when running session)
	var CurrentAgentID int
	// AgentList contains all the connected agents
	AgentList = make(map[int]*controller.LigoloAgent)
	// ListenerList contains all listener relays
	ListenerList = make(map[int]controller.Listener)

	App.AddCommand(&grumble.Command{
		Name:  "session",
		Help:  "Change the current relay agent",
		Usage: "session",
		Run: func(c *grumble.Context) error {
			AgentListMutex.Lock()
			if len(AgentList) == 0 {
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
						out = append(out, fmt.Sprintf("%d - %s", id, agent.String()))
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

			go func() {
				logrus.Infof("Starting tunnel to %s", CurrentAgent.Name)
				ligoloStack, err := proxy.NewLigoloTunnel(netstack.StackSettings{
					TunName:     c.Flags.String("tun"),
					MaxInflight: 4096,
				})
				if err != nil {
					logrus.Error("Unable to create tunnel, err:", err)
					return
				}
				ifName, err := ligoloStack.GetStack().Interface().Name()
				if err != nil {
					logrus.Warn("unable to get interface name, err:", err)
					ifName = c.Flags.String("tun")
				}
				CurrentAgent.Interface = ifName
				CurrentAgent.Running = true

				ctx, cancelTunnel := context.WithCancel(context.Background())
				go ligoloStack.HandleSession(CurrentAgent.Session, ctx)

				for {
					select {
					case <-CurrentAgent.CloseChan: // User stopped
						logrus.Infof("Closing tunnel to %s...", CurrentAgent.Name)
						cancelTunnel()
						return
					case <-CurrentAgent.Session.CloseChan(): // Agent closed
						logrus.Warnf("Lost connection with agent %s!", CurrentAgent.Name)
						// Connection lost, we need to delete the Agent from the list
						AgentListMutex.Lock()
						delete(AgentList, CurrentAgent.Id)
						AgentListMutex.Unlock()
						if CurrentAgent.Id == CurrentAgent.Id {
							App.SetDefaultPrompt()
							CurrentAgent.Session = nil
						}
						cancelTunnel()
						return
					}
				}
			}()
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

			for _, agent := range AgentList {

				if agent.Running {
					t.AppendRow(table.Row{agent.Id, agent.Name, agent.Interface})
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
			t.AppendHeader(table.Row{"#", "Agent", "Network", "Agent listener address", "Proxy redirect address"})

			ListenerListMutex.Lock()
			for id, listener := range ListenerList {
				t.AppendRow(table.Row{id, listener.Agent.String(), listener.Network, listener.ListenerAddr, listener.RedirectAddr})
			}
			ListenerListMutex.Unlock()
			c.App.Println(t.Render())
			return nil
		},
	})

	App.AddCommand(&grumble.Command{
		Name:      "listener_stop",
		Help:      "Stop a listener",
		Usage:     "listener_stop [id]",
		HelpGroup: "Listeners",
		Args: func(a *grumble.Args) {
			a.Int("id", "listener id")
		},
		Run: func(c *grumble.Context) error {
			if _, ok := AgentList[CurrentAgentID]; !ok {
				return ErrInvalidAgent
			}
			CurrentAgent := AgentList[CurrentAgentID]
			ListenerListMutex.Lock()
			if _, ok := ListenerList[c.Args.Int("id")]; !ok {
				ListenerListMutex.Unlock()
				return errors.New("invalid listener id")
			}
			listener := ListenerList[c.Args.Int("id")]
			ListenerListMutex.Unlock()
			listener.Session.Close()

			if err := proxy.ListenerStop(CurrentAgent.Session, listener.ListenerID); err != nil {
				return err
			}

			logrus.Info("Listener closed.")

			// Delete from the Listener List
			ListenerListMutex.Lock()
			delete(ListenerList, c.Args.Int("id"))
			ListenerListMutex.Unlock()

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
			f.BoolL("no-retry", false, "Do not restart relay on listener error")

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

			proxyListener, err := proxy.NewListener(CurrentAgent.Session, c.Flags.String("addr"), netProto, c.Flags.String("to"))
			if err != nil {
				return err
			}

			logrus.Infof("Listener %d created on remote agent!", proxyListener.ID)

			// Register the listener in the UI
			listener := controller.Listener{
				Agent:        *CurrentAgent,
				Network:      netProto,
				ListenerAddr: c.Flags.String("addr"),
				RedirectAddr: c.Flags.String("to"),
				Session:      proxyListener.Conn,
				ListenerID:   proxyListener.ID,
			}
			ListenerListMutex.Lock()
			ListenerList[controller.ListenerCounter] = listener
			ListenerListMutex.Unlock()
			controller.ListenerCounter++

			go func() {
				for {
					err := proxyListener.StartRelay()
					if err != nil {
						logrus.WithFields(logrus.Fields{"listener": listener.String()}).Error("Listener relay failed with error: ", err)
						if !c.Flags.Bool("no-retry") {
							logrus.Warning("Listener failed. Restarting in 5 seconds...")
							time.Sleep(time.Second * 5)
							continue
						}
						return
					}
					logrus.WithFields(logrus.Fields{"listener": listener.String()}).Warning("Listener ended without error.")
				}
			}()

			return nil
		},
	})
}

package app

import (
	"errors"
	"fmt"
	"github.com/AlecAivazis/survey/v2"
	"github.com/desertbit/grumble"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/nicocha30/ligolo-ng/pkg/controller"
	"github.com/nicocha30/ligolo-ng/pkg/protocol"
	"github.com/nicocha30/ligolo-ng/pkg/proxy/netstack"
	"github.com/nicocha30/ligolo-ng/pkg/relay"
	"github.com/sirupsen/logrus"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

var AgentList map[int]controller.LigoloAgent
var AgentListMutex sync.Mutex
var ListenerList map[int]controller.Listener
var ListenerListMutex sync.Mutex

var (
	ErrInvalidAgent   = errors.New("please, select an agent using the session command")
	ErrAlreadyRunning = errors.New("already running")
	ErrNotRunning     = errors.New("no tunnel started")
)

const (
	MaxConnectionHandler = 4096
)

func RegisterAgent(agent controller.LigoloAgent) error {
	AgentListMutex.Lock()
	AgentList[agent.Id] = agent
	AgentListMutex.Unlock()
	return nil
}

func Run(stackSettings netstack.StackSettings) {
	// CurrentAgent points to the selected agent in the UI (when running session)
	var CurrentAgent controller.LigoloAgent
	// ListeningAgent points to the currently running agent (forwarding packets)
	var ListeningAgent controller.LigoloAgent
	// AgentList contains all the connected agents
	AgentList = make(map[int]controller.LigoloAgent)
	// ListenerList contains all listener relays
	ListenerList = make(map[int]controller.Listener)

	// Create a new stack, but without connPool.
	// The connPool will be created when using the *start* command
	nstack := netstack.NewStack(stackSettings, nil)

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

			CurrentAgent = AgentList[sessionID]

			c.App.SetPrompt(fmt.Sprintf("[Agent : %s] » ", CurrentAgent.Name))

			return nil
		},
	})

	App.AddCommand(&grumble.Command{
		Name:      "start",
		Help:      "Start relaying connection to the current agent",
		Usage:     "start",
		HelpGroup: "Tunneling",
		Run: func(c *grumble.Context) error {
			if CurrentAgent.Session == nil {
				return ErrInvalidAgent
			}

			if ListeningAgent.Session != nil {
				if ListeningAgent.Id == CurrentAgent.Id {
					return ErrAlreadyRunning
				}

				if !ListeningAgent.Session.IsClosed() {
					var switchConfirm bool
					askSwitch := survey.Confirm{
						Message: fmt.Sprintf("Tunnel already running, switch from %s to %s?", ListeningAgent.Name, CurrentAgent.Name),
					}
					if err := survey.AskOne(&askSwitch, &switchConfirm); err != nil {
						return err
					}
					if !switchConfirm {
						return nil
					}
					// Close agent
					ListeningAgent.CloseChan <- true

				}
			}

			ListeningAgent = CurrentAgent

			go func() {
				logrus.Infof("Starting tunnel to %s", ListeningAgent.Name)

				// Create a new, empty, connpool to store connections/packets
				connPool := netstack.NewConnPool(MaxConnectionHandler)
				nstack.SetConnPool(&connPool)

				// Cleanup pool if channel is closed
				defer connPool.Close()

				for {
					select {
					case <-ListeningAgent.CloseChan: // User stopped
						logrus.Infof("Closing tunnel to %s...", ListeningAgent.Name)
						return
					case <-ListeningAgent.Session.CloseChan(): // Agent closed
						logrus.Warnf("Lost connection with agent %s!", ListeningAgent.Name)
						// Connection lost, we need to delete the Agent from the list
						AgentListMutex.Lock()
						delete(AgentList, ListeningAgent.Id)
						AgentListMutex.Unlock()
						if CurrentAgent.Id == ListeningAgent.Id {
							App.SetDefaultPrompt()
							CurrentAgent.Session = nil
						}
						return
					case <-connPool.CloseChan: // pool closed, we can't process packets!
						logrus.Infof("Connection pool closed")
						return
					case tunnelPacket := <-connPool.Pool: // Process connections/packets
						go netstack.HandlePacket(nstack.GetStack(), tunnelPacket, ListeningAgent.Session)
					}
				}
			}()
			return nil
		},
	})

	App.AddCommand(&grumble.Command{Name: "stop",
		Help:      "Stop the tunnel",
		Usage:     "stop",
		HelpGroup: "Tunneling",
		Run: func(c *grumble.Context) error {
			if ListeningAgent.Session == nil {
				return ErrNotRunning
			}
			ListeningAgent.CloseChan <- true
			ListeningAgent.Session = nil
			return nil
		},
	})
	App.AddCommand(&grumble.Command{
		Name:  "ifconfig",
		Help:  "Show agent interfaces",
		Usage: "ifconfig",
		Run: func(c *grumble.Context) error {
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
			ListenerListMutex.Lock()
			if _, ok := ListenerList[c.Args.Int("id")]; !ok {
				ListenerListMutex.Unlock()
				return errors.New("invalid listener id")
			}
			listener := ListenerList[c.Args.Int("id")]
			ListenerListMutex.Unlock()
			listener.Session.Close()

			yamuxConnectionSession, err := CurrentAgent.Session.Open()
			if err != nil {
				return err
			}
			protocolEncoder := protocol.NewEncoder(yamuxConnectionSession)
			protocolDecoder := protocol.NewDecoder(yamuxConnectionSession)

			// Send close request
			closeRequest := protocol.ListenerCloseRequestPacket{ListenerID: listener.ListenerID}
			if err := protocolEncoder.Encode(protocol.Envelope{
				Type:    protocol.MessageListenerCloseRequest,
				Payload: closeRequest,
			}); err != nil {
				return err
			}

			// Process close response
			if err := protocolDecoder.Decode(); err != nil {
				return err

			}
			response := protocolDecoder.Envelope.Payload

			if err := response.(protocol.ListenerCloseResponsePacket).Err; err != false {
				return errors.New(response.(protocol.ListenerCloseResponsePacket).ErrString)
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
		Usage:     "listener_add --addr [agent_listening_address:port] --to [local_listening_address:port] --tcp/--udp",
		HelpGroup: "Listeners",
		Flags: func(f *grumble.Flags) {
			f.BoolL("tcp", false, "Use TCP listener")
			f.BoolL("udp", false, "Use UDP listener")
			f.StringL("addr", "", "The agent listening address:port")
			f.StringL("to", "", "Where to redirect connections")

		},
		Run: func(c *grumble.Context) error {
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

			// Open a new Yamux Session
			yamuxConnectionSession, err := CurrentAgent.Session.Open()
			if err != nil {
				return err
			}
			protocolEncoder := protocol.NewEncoder(yamuxConnectionSession)
			protocolDecoder := protocol.NewDecoder(yamuxConnectionSession)

			// Request to open a new port on the agent
			listenerPacket := protocol.ListenerRequestPacket{Address: c.Flags.String("addr"), Network: netProto}
			if err := protocolEncoder.Encode(protocol.Envelope{
				Type:    protocol.MessageListenerRequest,
				Payload: listenerPacket,
			}); err != nil {
				return err
			}

			// Get response from agent
			if err := protocolDecoder.Decode(); err != nil {
				return err
			}
			response := protocolDecoder.Envelope.Payload.(protocol.ListenerResponsePacket)
			if err := response.Err; err != false {
				return errors.New(response.ErrString)
			}

			logrus.Info("Listener created on remote agent!")

			// Register the listener in the UI
			listener := controller.Listener{
				Agent:        CurrentAgent,
				Network:      netProto,
				ListenerAddr: c.Flags.String("addr"),
				RedirectAddr: c.Flags.String("to"),
				Session:      yamuxConnectionSession,
				ListenerID:   response.ListenerID,
			}
			ListenerListMutex.Lock()
			ListenerList[controller.ListenerCounter] = listener
			ListenerListMutex.Unlock()
			currentListener := controller.ListenerCounter
			controller.ListenerCounter++

			if netProto == "udp" {

				// relay connections
				go func() {
					for {
						// Check if deleted
						if _, ok := ListenerList[currentListener]; !ok {
							return
						}
						// Dial the "to" target
						lconn, err := net.Dial(netProto, c.Flags.String("to"))
						if err != nil {
							logrus.Error(err)
							return
						}
						// Relay conn
						err = relay.StartPacketRelay(lconn, yamuxConnectionSession)
						if err != nil {
							logrus.WithFields(logrus.Fields{"listener": ListenerList[currentListener].String(), "error": err}).Error("Failed to relay UDP connection. Make sure that you are 'to' host is listening! Retrying...")
						}
						time.Sleep(2 * time.Second)
					}
				}()
			}

			if netProto == "tcp" {
				go func() {
					for {
						// Wait for BindResponses
						if err := protocolDecoder.Decode(); err != nil {
							if err == io.EOF {
								// Listener closed.
								return
							}
							logrus.Error(err)
							return
						}

						// We received a new BindResponse!
						response := protocolDecoder.Envelope.Payload.(protocol.ListenerBindReponse)

						if err := response.Err; err != false {
							logrus.Error(response.ErrString)
							return
						}

						logrus.Debugf("New socket opened : %d", response.SockID)

						// relay connection
						go func(sockID int32) {

							forwarderSession, err := CurrentAgent.Session.Open()
							if err != nil {
								logrus.Error(err)
								return
							}

							protocolEncoder := protocol.NewEncoder(forwarderSession)
							protocolDecoder := protocol.NewDecoder(forwarderSession)

							// Request socket access
							socketRequestPacket := protocol.ListenerSockRequestPacket{SockID: sockID}
							if err := protocolEncoder.Encode(protocol.Envelope{
								Type:    protocol.MessageListenerSockRequest,
								Payload: socketRequestPacket,
							}); err != nil {
								logrus.Error(err)
								return
							}
							if err := protocolDecoder.Decode(); err != nil {
								logrus.Error(err)
								return
							}

							response := protocolDecoder.Envelope.Payload
							if err := response.(protocol.ListenerSockResponsePacket).Err; err != false {
								logrus.Error(response.(protocol.ListenerSockResponsePacket).ErrString)
								return
							}
							// Got socket access!

							logrus.Debug("Listener relay established!")

							// Dial the "to" target
							lconn, err := net.Dial(netProto, c.Flags.String("to"))
							if err != nil {
								logrus.Error(err)
								return
							}

							// relay connections
							relay.StartRelay(lconn, forwarderSession)
						}(response.SockID)

					}

				}()
			}

			return nil
		},
	})
}

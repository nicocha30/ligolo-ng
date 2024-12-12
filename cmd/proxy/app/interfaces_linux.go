package app

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/desertbit/grumble"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/nicocha30/ligolo-ng/pkg/proxy/netstack/tun"
	"github.com/nicocha30/ligolo-ng/pkg/utils/codenames"
	"github.com/sirupsen/logrus"
)

func init() {
	interfaceCmd := &grumble.Command{
		Name:    "interface",
		Help:    "Manage interfaces",
		Aliases: []string{"if"},
	}

	App.AddCommand(interfaceCmd)

	interfaceCmd.AddCommand(&grumble.Command{
		Name: "ls",
		Help: "List available tuntap interfaces",
		Run: func(c *grumble.Context) error {
			t := table.NewWriter()
			t.SetStyle(table.StyleLight)
			t.SetTitle("Available tuntaps")
			t.AppendHeader(table.Row{"#", "Tap Name", "Dst routes"})

			tuntaps, err := tun.GetTunTaps()
			if err != nil {
				return err
			}

			for i, tuntap := range tuntaps {
				var prettyRoute []string
				for _, route := range tuntap.Routes() {
					prettyRoute = append(prettyRoute, route.Dst.String())
				}

				t.AppendRow(table.Row{i, tuntap.Name(), strings.Join(prettyRoute, ",")})
			}

			App.Println(t.Render())
			return nil
		},
	})

	interfaceCmd.AddCommand(&grumble.Command{
		Name: "create",
		Help: "Create a new tuntap interface",
		Args: func(a *grumble.Args) {
			a.String("name", "Name of tuntap interface to create")
		},
		Run: func(c *grumble.Context) error {
			ifName := c.Args.String("name")
			if ifName == "" {
				return errors.New("please specify a name")
			}

			logrus.Infof("Creating a new \"%s\" interface...", ifName)

			if err := tun.CreateTUN(ifName); err != nil {
				return err
			}

			logrus.Info("Interface created!")
			return nil
		},
	})

	interfaceCmd.AddCommand(&grumble.Command{
		Name: "rm",
		Help: "Remove a tuntap interface",
		Args: func(a *grumble.Args) {
			a.String("name", "Name or index of tuntap interface to remove")
		},
		Run: func(c *grumble.Context) error {
			ifName := c.Args.String("name")
			if ifName == "" {
				return errors.New("please specify a valid interface")
			}

			tuntaps, err := tun.GetTunTaps()
			if err != nil {
				return err
			}

			index, err := strconv.Atoi(ifName)
			if err != nil {
				// Fetch ifName by name
				stun, err := tun.GetTunByName(ifName)
				if err != nil {
					return errors.New(fmt.Sprintf("No tap name with '%s'", ifName))
				}

				if err := stun.Destroy(); err != nil {
					return err
				}

				logrus.Info(fmt.Sprintf("Removed interface '%s'", ifName))
				return nil
			}

			// Fetch ifName by index
			if index >= 0 && index < len(tuntaps) {
				stun := tuntaps[index]
				if err := stun.Destroy(); err != nil {
					return err
				}
			} else {
				return errors.New(fmt.Sprintf("Invalid index '%s'", ifName))
			}

			logrus.Info(fmt.Sprintf("Removed interface '%s'", tuntaps[index].Name()))
			return nil
		},
	})

	routeCmd := &grumble.Command{
		Name: "route",
		Help: "Manage routes",
	}

	App.AddCommand(routeCmd)

	routeCmd.AddCommand(&grumble.Command{
		Name: "ls",
		Help: "List available routes",
		Run: func(c *grumble.Context) error {
			t := table.NewWriter()
			t.SetStyle(table.StyleLight)
			t.SetTitle("Available tuntaps")
			t.AppendHeader(table.Row{"#", "Tap Name", "Dst routes"})

			tuntaps, err := tun.GetTunTaps()
			if err != nil {
				return err
			}

			for i, tuntap := range tuntaps {
				var prettyRoute []string
				for _, route := range tuntap.Routes() {
					prettyRoute = append(prettyRoute, route.Dst.String())
				}

				t.AppendRow(table.Row{i, tuntap.Name(), strings.Join(prettyRoute, ",")})
			}

			App.Println(t.Render())
			return nil
		},
	})

	routeCmd.AddCommand(&grumble.Command{
		Name:  "add",
		Help:  "Add a route to a network interface",
		Usage: "route add [ifname] [cidr]",
		Args: func(a *grumble.Args) {
			a.String("name", "Name of interface")
			a.String("cidr", "The network CIDR")
		},
		Run: func(c *grumble.Context) error {
			ifName := c.Args.String("name")
			cidr := c.Args.String("cidr")

			if ifName == "" {
				return errors.New("please specify a name")
			}

			if cidr == "" {
				return errors.New("please specify a CIDR")
			}

			stun, err := tun.GetTunByName(ifName)
			if err != nil {
				return err
			}

			if err := stun.AddRoute(cidr); err != nil {
				return err
			}

			logrus.Info("Route created")
			return nil
		},
	})

	routeCmd.AddCommand(&grumble.Command{
		Name:  "rm",
		Help:  "Remove a route",
		Usage: "route rm [ifname] [cidr]",
		Args: func(a *grumble.Args) {
			a.String("name", "Name of interface")
			a.String("cidr", "The network CIDR")
		},
		Run: func(c *grumble.Context) error {
			ifName := c.Args.String("name")
			routeCidr := c.Args.String("cidr")

			stun, err := tun.GetTunByName(ifName)
			if err != nil {
				return err
			}

			if err := stun.DelRoute(routeCidr); err != nil {
				return err
			}

			logrus.Info("Route deleted.")
			return nil

		},
	})

	App.AddCommand(&grumble.Command{
		Name:  "autoroute",
		Help:  "Setup everything for you (interfaces, routes & tunnel)",
		Usage: "autoroute",
		Flags: func(f *grumble.Flags) {
			f.BoolL("with-ipv6", false, "Include IPv6 addresses")
		},
		Run: func(c *grumble.Context) error {

			if _, ok := AgentList[CurrentAgentID]; !ok {
				return ErrInvalidAgent
			}
			CurrentAgent := AgentList[CurrentAgentID]
			// Note: Network information is not refreshed when calling this command
			if CurrentAgent.Session == nil {
				return ErrInvalidAgent
			}
			var possibleRoutes []string
			for _, ifaceInfo := range CurrentAgent.Network {
				for _, address := range ifaceInfo.Addresses {
					ip, _, err := net.ParseCIDR(address)
					if err != nil {
						continue
					}
					if !ip.IsLoopback() {
						if ip.To4() != nil || c.Flags.Bool("with-ipv6") {
							possibleRoutes = append(possibleRoutes, address)
						}
					}
				}
			}
			routePrompt := &survey.MultiSelect{
				Message: "Select routes to add:",
				Options: possibleRoutes,
			}
			var selectedRoutes []string
			if err := survey.AskOne(routePrompt, &selectedRoutes); err != nil {
				return err
			}
			if len(selectedRoutes) == 0 {
				return errors.New("no route selected")
			}
			var ifaceSelectionPrompt string
			if err := survey.AskOne(&survey.Select{Message: "Create a new interface or use an existing one?", Options: []string{"Create a new interface", "Use an existing one"}}, &ifaceSelectionPrompt); err != nil {
				return err
			}

			var selectedIface string
			if ifaceSelectionPrompt == "Create a new interface" {
				logrus.Info("Generating a random interface name...")
				rng, err := codenames.DefaultRNG()
				if err != nil {
					return err
				}

				ifName := codenames.Generate(rng)

				logrus.Infof("Creating a new \"%s\" interface...", ifName)
				if err := tun.CreateTUN(ifName); err != nil {
					return err
				}
				selectedIface = ifName
			} else {
				ifaces, err := net.Interfaces()
				if err != nil {
					return err
				}
				var ifaceNames []string
				for _, iface := range ifaces {
					ifaceNames = append(ifaceNames, iface.Name)
				}
				if err := survey.AskOne(&survey.Select{Message: "Select the interface to use", Options: ifaceNames}, &selectedIface); err != nil {
					return err
				}
			}
			logrus.Infof("Using interface %s, creating routes...", selectedIface)
			stun, err := tun.GetTunByName(selectedIface)
			if err != nil {
				return err
			}
			for _, route := range selectedRoutes {
				if err := stun.AddRoute(route); err != nil {
					logrus.Errorf("Could not add route %s: %v", route, err)
					continue
				}
				logrus.Infof("Route %s created.", route)
			}

			startTunnel := false
			prompt := &survey.Confirm{
				Message: "Start the tunnel?",
			}
			survey.AskOne(prompt, &startTunnel)

			if startTunnel {
				go StartTunnel(CurrentAgent, selectedIface)
			} else {
				logrus.Infof("You can start the tunnel with: start --tun %s", selectedIface)
			}

			return nil
		},
	})
}

package app

import (
	"errors"
	"fmt"
	"github.com/AlecAivazis/survey/v2"
	"github.com/desertbit/grumble"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/nicocha30/ligolo-ng/pkg/proxy/netstack/tun"
	"github.com/nicocha30/ligolo-ng/pkg/utils/codenames"
	"github.com/sirupsen/logrus"
	"net"
	"strings"
)

func init() {

	App.AddCommand(&grumble.Command{
		Name:      "interface_list",
		Aliases:   []string{"iflist", "route_list"},
		Help:      "List available tun interfaces",
		Usage:     "interface_list",
		HelpGroup: "Interfaces",
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

	App.AddCommand(&grumble.Command{
		Name:      "interface_create",
		Aliases:   []string{"ifcreate"},
		Help:      "Create a new tuntap interface",
		Usage:     "interface_create --name [ifname]",
		HelpGroup: "Interfaces",
		Flags: func(f *grumble.Flags) {
			f.StringL("name", "", "the interface name to create (if empty, will use a generated name)")
		},
		Run: func(c *grumble.Context) error {

			ifName := c.Flags.String("name")
			if ifName == "" {
				logrus.Info("Generating a random interface name...")
				rng, err := codenames.DefaultRNG()
				if err != nil {
					return err
				}

				ifName = codenames.Generate(rng)
			}
			logrus.Infof("Creating a new \"%s\" interface...", ifName)
			if err := tun.CreateTUN(ifName); err != nil {
				return err
			}
			logrus.Info("Interface created!")
			return nil
		},
	})

	App.AddCommand(&grumble.Command{
		Name:      "interface_delete",
		Aliases:   []string{"ifdel"},
		Help:      "Delete a tuntap interface",
		Usage:     "interface_delete --name [ifname]",
		HelpGroup: "Interfaces",
		Flags: func(f *grumble.Flags) {
			f.StringL("name", "", "the interface name to delete")
		},
		Run: func(c *grumble.Context) error {

			ifName := c.Flags.String("name")
			if ifName == "" {
				return errors.New("please specify a valid interface using --name [interface]")
			}
			stun, err := tun.GetTunByName(ifName)
			if err != nil {
				return err
			}
			if err := stun.Destroy(); err != nil {
				return err
			}
			logrus.Info("Interface destroyed.")
			return nil
		},
	})

	App.AddCommand(&grumble.Command{
		Name:      "route_add",
		Aliases:   []string{"add_route", "interface_route_add", "interface_add_route"},
		Help:      "Add a route to a network interface",
		Usage:     "route_add --name [ifname] --route [cidr]",
		HelpGroup: "Interfaces",
		Flags: func(f *grumble.Flags) {
			f.StringL("name", "", "the interface name")
			f.StringL("route", "", "the network cidr")
		},
		Run: func(c *grumble.Context) error {

			ifName := c.Flags.String("name")
			if ifName == "" {
				return errors.New("please specify an interface")
			}
			routeCidr := c.Flags.String("route")
			if routeCidr == "" {
				return errors.New("please specify a route")
			}

			stun, err := tun.GetTunByName(ifName)
			if err != nil {
				return err
			}
			if err := stun.AddRoute(routeCidr); err != nil {
				return err
			}
			logrus.Info("Route created.")
			return nil
		},
	})

	App.AddCommand(&grumble.Command{
		Name:      "route_del",
		Aliases:   []string{"del_route", "interface_route_del", "interface_del_route"},
		Help:      "Delete a route",
		Usage:     "route_del --name [ifname] --route [cidr]",
		HelpGroup: "Interfaces",
		Flags: func(f *grumble.Flags) {
			f.StringL("name", "", "the interface name")
			f.StringL("route", "", "the network cidr")
		},
		Run: func(c *grumble.Context) error {

			routeCidr := c.Flags.String("route")
			if routeCidr == "" {
				tuntaps, err := tun.GetTunTaps()
				if err != nil {
					return err
				}
				var possibleRoutes []string
				for _, tuntap := range tuntaps {
					for _, route := range tuntap.Routes() {
						possibleRoutes = append(possibleRoutes, fmt.Sprintf("%s (%s)", route.Dst.String(), tuntap.Name()))
					}
				}
				if len(possibleRoutes) == 0 {
					return errors.New("no routes available")
				}

				routePrompt := &survey.MultiSelect{
					Message: "Select routes to delete:",
					Options: possibleRoutes,
				}
				var selectedRoutes []string
				if err := survey.AskOne(routePrompt, &selectedRoutes); err != nil {
					return err
				}
				for _, selectedRoute := range selectedRoutes {
					route := strings.Split(selectedRoute, " ")[0]
					ifByRoute, err := tun.GetTunByRoute(route)
					if err != nil {
						logrus.Errorf("Failed to get tuntap by route \"%s\": %v", route, err)
					}
					if err := ifByRoute.DelRoute(route); err != nil {
						logrus.Errorf("Failed to delete route \"%s\": %v", route, err)
					}
				}
				return nil
			}
			ifName := c.Flags.String("name")
			if ifName == "" {
				// Attempt to search for route.
				ifByRoute, err := tun.GetTunByRoute(routeCidr)
				if err != nil {
					return err
				}
				ifName = ifByRoute.Name()
			}

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
		Name:      "autoroute",
		Help:      "Setup everything for you (interfaces, routes & tunnel)",
		HelpGroup: "Tunneling",
		Usage:     "autoroute",
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

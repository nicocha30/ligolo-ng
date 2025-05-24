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

//go:build windows || linux || freebsd || openbsd || darwin

package app

import (
	"errors"
	"fmt"
	"github.com/AlecAivazis/survey/v2"
	"github.com/desertbit/grumble"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/nicocha30/ligolo-ng/cmd/proxy/config"
	"github.com/nicocha30/ligolo-ng/pkg/proxy/netinfo"
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
			t.SetTitle("Interface list")
			t.AppendHeader(table.Row{"#", "Tap Name", "Dst routes", "State"})

			interfaces, err := config.GetInterfaceConfigState()
			if err != nil {
				return err
			}

			var i int
			for tapName, tapInfo := range interfaces {
				t.AppendRow(table.Row{i, tapName, tapInfo.GetRouteString(), tapInfo.GetStateString()})
				i++
			}
			App.Println(t.Render())
			App.Println(text.Colors{text.FgYellow}.Sprintf("Interfaces and routes with \"Pending\" state will be created on tunnel start."))
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
			if err := config.AddInterfaceConfig(ifName); err != nil {
				return err
			}
			if netinfo.CanCreateTUNs() {
				logrus.Infof("Creating a new %s interface...", ifName)
				if err := netinfo.CreateTUN(ifName); err != nil {
					return err
				}
				logrus.Info("Interface created!")

			} else {
				logrus.Infof("Interface will %s be created on tunnel start.", ifName)
			}
			return nil
		},
	})

	App.AddCommand(&grumble.Command{
		Name:      "interface_delete",
		Aliases:   []string{"ifdel", "interface_del"},
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
			if config.GetInterfaceConfig(ifName) != nil {
				if ask("Remove all interface routes and settings from config?") {
					if err := config.DeleteInterfaceConfig(ifName); err != nil {
						return err
					}
				}
			}

			if netinfo.InterfaceExist(ifName) {
				stun, err := netinfo.GetTunByName(ifName)
				if err != nil {
					return err
				}
				if err := stun.Destroy(); err != nil {
					return err
				}
				logrus.Info("Interface removed.")
			}
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

			if err := config.AddRouteConfig(ifName, routeCidr); err != nil {
				return err
			}

			if netinfo.InterfaceExist(ifName) {
				stun, err := netinfo.GetTunByName(ifName)
				if err != nil {
					return err
				}
				if err := stun.AddRoute(routeCidr); err != nil {
					return err
				}
				logrus.Info("Route created.")
			} else {
				logrus.Infof("Route %s on %s be added on tunnel start.", routeCidr, ifName)
			}
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

			interfaces, err := config.GetInterfaceConfigState()
			if err != nil {
				return err
			}

			routeCidr := c.Flags.String("route")
			if routeCidr == "" {
				var possibleRoutes []string
				for ifName, ifInfo := range interfaces {
					for _, route := range ifInfo.Routes {
						possibleRoutes = append(possibleRoutes, fmt.Sprintf("%s (%s)", route.Destination, ifName))
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
					routeSelection := strings.Split(selectedRoute, " ")[0]

					for ifName, ifInfo := range interfaces {
						for _, route := range ifInfo.Routes {
							if route.Destination == routeSelection {
								if route.Active {
									tun, err := netinfo.GetTunByName(ifName)
									if err != nil {
										return err
									}
									if err := tun.DelRoute(route.Destination); err != nil {
										logrus.Errorf("Could not delete route %s: %s", route.Destination, err)
									}
								}
								if err := config.DeleteRouteConfig(ifName, route.Destination); err != nil {
									logrus.Errorf("Could not delete route %s from config: %s", route.Destination, err)
								}
							}
						}
					}
				}
				return nil
			}
			ifName := c.Flags.String("name")
			if ifName == "" {
				// Attempt to search for route.
				ifByRoute, err := netinfo.GetTunByRoute(routeCidr)
				if err != nil {
					return err
				}
				ifName = ifByRoute.Name()
			}

			stun, err := netinfo.GetTunByName(ifName)
			if err != nil {
				return err
			}
			if err := config.DeleteRouteConfig(ifName, routeCidr); err != nil {
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

				logrus.Infof("Using interface name %s", ifName)
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

			if err := config.AddInterfaceConfig(selectedIface); err != nil {
				return fmt.Errorf("could not add interface to config: %s", err)
			}

			logrus.Infof("Creating routes for %s...", selectedIface)

			for _, route := range selectedRoutes {
				if err := config.AddRouteConfig(selectedIface, route); err != nil {
					logrus.Errorf("Could not add route %s: %s", route, err)
				}
			}

			startTunnel := false
			prompt := &survey.Confirm{
				Message: "Start the tunnel?",
			}
			survey.AskOne(prompt, &startTunnel)

			if startTunnel {
				if err := StartTunnel(CurrentAgent, selectedIface); err != nil {
					return fmt.Errorf("unable to start tunnel: %v", err)
				}
			} else {
				logrus.Infof("You can start the tunnel with: start --tun %s", selectedIface)
			}

			return nil
		},
	})

}

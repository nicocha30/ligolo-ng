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
	"net"
	"sort"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/desertbit/grumble"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/nicocha30/ligolo-ng/cmd/proxy/config"
	"github.com/nicocha30/ligolo-ng/pkg/proxy/netinfo"
	"github.com/nicocha30/ligolo-ng/pkg/utils/codenames"
	"github.com/sirupsen/logrus"
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
		Usage:     "interface_delete [--name ifname | --id number]",
		HelpGroup: "Interfaces",
		Flags: func(f *grumble.Flags) {
			f.String("n", "name", "", "the interface name to delete")
			f.Int("i", "id", -1, "the interface ID to delete (from interface_list)")
		},
		Run: func(c *grumble.Context) error {
			ifName := c.Flags.String("name")
			ifID := c.Flags.Int("id")
			
			// If neither name nor ID provided, show error
			if ifName == "" && ifID == -1 {
				return errors.New("please specify either --name [interface] or --id [number]")
			}
			
			// If ID is provided, look up the interface name
			if ifID != -1 {
				interfaces, err := config.GetInterfaceConfigState()
				if err != nil {
					return err
				}
				
				// Convert map to slice to access by index
				var interfaceNames []string
				for name := range interfaces {
					interfaceNames = append(interfaceNames, name)
				}
				
				// Sort to ensure consistent ordering
				sort.Strings(interfaceNames)
				
				if ifID < 0 || ifID >= len(interfaceNames) {
					return fmt.Errorf("invalid interface ID: %d. Use 'interface_list' to see valid IDs", ifID)
				}
				
				ifName = interfaceNames[ifID]
				logrus.Infof("Deleting interface #%d: %s", ifID, ifName)
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
		Usage:     "route_del [--name ifname --route cidr | --id number]",
		HelpGroup: "Interfaces",
		Flags: func(f *grumble.Flags) {
			f.String("n", "name", "", "the interface name")
			f.StringL("route", "", "the network cidr")
			f.Int("i", "id", -1, "the route ID to delete (from interface_list, 0-indexed across all routes)")
		},
		Run: func(c *grumble.Context) error {

			interfaces, err := config.GetInterfaceConfigState()
			if err != nil {
				return err
			}

			routeCidr := c.Flags.String("route")
			ifName := c.Flags.String("name")
			routeID := c.Flags.Int("id")
			
			// If ID is provided, look up the route and interface
			if routeID != -1 {
				// Build a flat list of all routes with their interface names
				type RouteEntry struct {
					ifaceName string
					route     string
				}
				var allRoutes []RouteEntry
				
				// Get interfaces in sorted order for consistent IDs
				var ifaceNames []string
				for name := range interfaces {
					ifaceNames = append(ifaceNames, name)
				}
				sort.Strings(ifaceNames)
				
				for _, ifaceName := range ifaceNames {
					ifInfo := interfaces[ifaceName]
					for _, route := range ifInfo.Routes {
						allRoutes = append(allRoutes, RouteEntry{
							ifaceName: ifaceName,
							route:     route.Destination,
						})
					}
				}
				
				if routeID < 0 || routeID >= len(allRoutes) {
					return fmt.Errorf("invalid route ID: %d. Total routes: %d", routeID, len(allRoutes))
				}
				
				selectedRoute := allRoutes[routeID]
				ifName = selectedRoute.ifaceName
				routeCidr = selectedRoute.route
				logrus.Infof("Deleting route #%d: %s on interface %s", routeID, routeCidr, ifName)
				
				// Delete the route
				ifInfo := interfaces[ifName]
				for _, route := range ifInfo.Routes {
					if route.Destination == routeCidr {
						if route.Active {
							tun, err := netinfo.GetTunByName(ifName)
							if err != nil {
								return err
							}
							if err := tun.DelRoute(route.Destination); err != nil {
								return fmt.Errorf("could not delete route %s: %s", route.Destination, err)
							}
						}
						if err := config.DeleteRouteConfig(ifName, route.Destination); err != nil {
							return fmt.Errorf("could not delete route %s from config: %s", route.Destination, err)
						}
						logrus.Info("Route deleted.")
						return nil
					}
				}
				return errors.New("route not found")
			}
			
			// Original interactive or named route deletion logic
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
		Usage:     "autoroute [--interface name]",
		Flags: func(f *grumble.Flags) {
			f.BoolL("with-ipv6", false, "Include IPv6 addresses")
			f.StringL("interface", "", "Custom interface name (if provided, skips interface creation prompt)")
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

			var selectedIface string
			customName := c.Flags.String("interface")
			
			// If --interface flag is provided, use it directly without prompting
			if customName != "" {
				logrus.Infof("Using custom interface name: %s", customName)
				selectedIface = customName
				
				// Check if interface physically exists
				if netinfo.InterfaceExist(selectedIface) {
					logrus.Warnf("Interface %s already exists physically", selectedIface)
					// Check if it's being used by current agent
					if CurrentAgent.Running && CurrentAgent.Interface == selectedIface {
						return fmt.Errorf("interface %s is already in use by this agent. Please stop the tunnel first with 'stop' command", selectedIface)
					}
					// Check if it's being used by another agent
					for _, agent := range AgentList {
						if agent.Running && agent.Interface == selectedIface {
							return fmt.Errorf("interface %s is already in use by agent %s. Please use a different interface name", selectedIface, agent.Name)
						}
					}
				}
			} else {
				// Only ask if user wants to create new or use existing if no --interface flag
				var ifaceSelectionPrompt string
				if err := survey.AskOne(&survey.Select{Message: "Create a new interface or use an existing one?", Options: []string{"Create a new interface", "Use an existing one"}}, &ifaceSelectionPrompt); err != nil {
					return err
				}

				if ifaceSelectionPrompt == "Create a new interface" {
					// Prompt for custom interface name
					var customIfaceName string
					ifaceNamePrompt := &survey.Input{
						Message: "Enter interface name (leave empty for random name):",
					}
					if err := survey.AskOne(ifaceNamePrompt, &customIfaceName); err != nil {
						return err
					}
					
					var ifName string
					if customIfaceName != "" {
						// User provided a custom name
						ifName = customIfaceName
						logrus.Infof("Using custom interface name: %s", ifName)
						
						// Check if it already exists
						if netinfo.InterfaceExist(ifName) {
							logrus.Warnf("Interface %s already exists physically", ifName)
							// Check if it's being used by any agent
							for _, agent := range AgentList {
								if agent.Running && agent.Interface == ifName {
									return fmt.Errorf("interface %s is already in use by agent %s. Please use a different interface name", ifName, agent.Name)
								}
							}
						}
					} else {
						// Generate a random name
						logrus.Info("Generating a random interface name...")
						rng, err := codenames.DefaultRNG()
						if err != nil {
							return err
						}

						ifName = codenames.Generate(rng)
						
						// Make sure the randomly generated name doesn't already exist
						for netinfo.InterfaceExist(ifName) {
							logrus.Warnf("Interface %s already exists, generating a new name...", ifName)
							ifName = codenames.Generate(rng)
						}

						logrus.Infof("Using interface name %s", ifName)
					}
					selectedIface = ifName

				} else {
					// Get interface configurations to show routes
					interfaces, err := config.GetInterfaceConfigState()
					if err != nil {
						return err
					}

					var ifaceOptions []string
					ifaceMap := make(map[string]string)
					for ifName, ifInfo := range interfaces {
						displayName := ifName
						if len(ifInfo.Routes) > 0 {
							// Get routes and display them in yellow
							var routes []string
							for _, route := range ifInfo.Routes {
								routes = append(routes, route.Destination)
							}
							routeStr := strings.Join(routes, ", ")
							yellowRoutes := text.Colors{text.FgYellow}.Sprintf(routeStr)
							displayName = fmt.Sprintf("%s %s", ifName, yellowRoutes)
						}
						ifaceOptions = append(ifaceOptions, displayName)
						ifaceMap[displayName] = ifName
					}

					if len(ifaceOptions) == 0 {
						return errors.New("no interfaces available, create a new one first")
					}

					var selectedIfaceDisplay string
					if err := survey.AskOne(&survey.Select{
						Message: "Select the interface to use",
						Options: ifaceOptions,
					}, &selectedIfaceDisplay); err != nil {
						return err
					}

					selectedIface = ifaceMap[selectedIfaceDisplay]
					
					// Check if the selected existing interface is being used by another agent
					for _, agent := range AgentList {
						if agent.Running && agent.Interface == selectedIface && agent != CurrentAgent {
							return fmt.Errorf("interface %s is already in use by agent %s. Please select a different interface", selectedIface, agent.Name)
						}
					}
				}
			}

			// Final check: if interface physically exists but no agent is using it, delete and recreate it
			if netinfo.InterfaceExist(selectedIface) {
				// Double-check no agent is using it
				interfaceInUse := false
				for _, agent := range AgentList {
					if agent.Running && agent.Interface == selectedIface {
						interfaceInUse = true
						break
					}
				}
				
				if !interfaceInUse {
					logrus.Warnf("Interface %s exists but is not in use. Removing it to avoid conflicts...", selectedIface)
					stun, err := netinfo.GetTunByName(selectedIface)
					if err == nil {
						if err := stun.Destroy(); err != nil {
							logrus.Warnf("Could not destroy interface %s: %v", selectedIface, err)
						}
					}
				}
			}

			// Check if interface already exists and has an active tunnel
			if CurrentAgent.Running && CurrentAgent.Interface == selectedIface {
				return fmt.Errorf("interface %s is already in use by this agent. Please stop the tunnel first with 'stop' command", selectedIface)
			}

			// Only add to config, don't create the physical interface
			// The interface will be created when StartTunnel is called
			if err := config.AddInterfaceConfig(selectedIface); err != nil {
				return fmt.Errorf("could not add interface to config: %s", err)
			}
			logrus.Infof("Interface %s configured (will be created on tunnel start)", selectedIface)

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

// Ligolo-ng Relay
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
	"sort"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/allsmog/ligolo-ng-relay/cmd/proxy/config"
	"github.com/allsmog/ligolo-ng-relay/pkg/proxy/netinfo"
	"github.com/allsmog/ligolo-ng-relay/pkg/utils/codenames"
	"github.com/desertbit/grumble"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
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

			// Sort interface names for consistent ordering
			var interfaceNames []string
			for name := range interfaces {
				interfaceNames = append(interfaceNames, name)
			}
			sort.Strings(interfaceNames)

			// Build table with sorted interfaces
			for i, tapName := range interfaceNames {
				tapInfo := interfaces[tapName]
				t.AppendRow(table.Row{i, tapName, tapInfo.GetRouteString(), tapInfo.GetStateString()})
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

				// Sort interface names to match interface_list ordering
				var interfaceNames []string
				for name := range interfaces {
					interfaceNames = append(interfaceNames, name)
				}
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
		Usage:     "autoroute [--agent id] [--interface name]",
		Flags: func(f *grumble.Flags) {
			f.IntL("agent", 0, "Agent ID to autoroute (defaults to the current session)")
			f.BoolL("with-ipv6", false, "Include IPv6 addresses")
			f.StringL("interface", "", "Custom interface name (if provided, skips interface creation prompt)")
		},
		Run: func(c *grumble.Context) error {
			agentID := c.Flags.Int("agent")
			if agentID == 0 {
				agentID = CurrentAgentID
			}
			if _, ok := AgentList[agentID]; !ok {
				return ErrInvalidAgent
			}
			CurrentAgent := AgentList[agentID]
			// Note: Network information is not refreshed when calling this command
			if CurrentAgent.Session == nil {
				return ErrInvalidAgent
			}
			possibleRoutes := candidateRoutes(CurrentAgent, c.Flags.Bool("with-ipv6"))
			if len(possibleRoutes) == 0 {
				return errors.New("no routes available for selected agent")
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
							yellowRoutes := text.Colors{text.FgYellow}.Sprintf("%s", routeStr)
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

	App.AddCommand(&grumble.Command{
		Name:      "chain_routes",
		Help:      "Show route candidates across all online agents",
		Usage:     "chain_routes [--with-ipv6] [--interface-prefix prefix]",
		HelpGroup: "Relay",
		Flags: func(f *grumble.Flags) {
			f.BoolL("with-ipv6", false, "Include IPv6 addresses")
			f.StringL("interface-prefix", "ligolo", "Interface name prefix used for suggested chain autoroutes")
		},
		Run: func(c *grumble.Context) error {
			routes := chainRouteInfos(c.Flags.Bool("with-ipv6"), c.Flags.String("interface-prefix"))
			if len(routes) == 0 {
				return errors.New("no route candidates available")
			}

			t := table.NewWriter()
			t.SetStyle(table.StyleLight)
			t.SetTitle("Chain route candidates")
			t.AppendHeader(table.Row{"Agent ID", "Agent", "Hop", "Via", "Interface", "Route", "Warning"})
			for _, route := range routes {
				via := "direct"
				if route.ParentSessionID != "" {
					via = route.ParentSessionID
				}
				t.AppendRow(table.Row{route.AgentID, route.Name, route.HopDepth, via, route.Interface, route.Route, route.Warning})
			}
			App.Println(t.Render())
			return nil
		},
	})

	App.AddCommand(&grumble.Command{
		Name:      "chain_plan",
		Help:      "Preview smart route decisions across the relay chain",
		Usage:     "chain_plan [--interface-prefix ligolo] [--with-ipv6] [--start]",
		HelpGroup: "Relay",
		Flags: func(f *grumble.Flags) {
			f.BoolL("with-ipv6", false, "Include IPv6 addresses")
			f.StringL("interface-prefix", "ligolo", "Interface name prefix for generated interface configs")
			f.BoolL("start", false, "Include tunnel start actions in the dry-run plan")
		},
		Run: func(c *grumble.Context) error {
			plan := chainRoutePlan(c.Flags.Bool("with-ipv6"), c.Flags.String("interface-prefix"), c.Flags.Bool("start"))
			if len(plan.Decisions) == 0 {
				return errors.New("no route candidates available")
			}

			t := table.NewWriter()
			t.SetStyle(table.StyleLight)
			t.SetTitle("Smart chain route plan")
			t.AppendHeader(table.Row{"Decision", "Agent ID", "Agent", "Hop", "Interface", "Route", "Score", "Reason"})
			for _, decision := range plan.Decisions {
				t.AppendRow(table.Row{decision.Decision, decision.AgentID, decision.Name, decision.HopDepth, decision.Interface, decision.Route, decision.Score, decision.Reason})
			}
			App.Println(t.Render())
			return nil
		},
	})

	App.AddCommand(&grumble.Command{
		Name:      "chain_autoroute",
		Help:      "Configure selected per-agent interfaces and routes across the relay chain",
		Usage:     "chain_autoroute [--interface-prefix ligolo] [--with-ipv6] [--start]",
		HelpGroup: "Relay",
		Flags: func(f *grumble.Flags) {
			f.BoolL("with-ipv6", false, "Include IPv6 addresses")
			f.StringL("interface-prefix", "ligolo", "Interface name prefix for generated interface configs")
			f.BoolL("start", false, "Start tunnels after configuring routes")
		},
		Run: func(c *grumble.Context) error {
			routes, err := configureChainAutoroutes(c.Flags.Bool("with-ipv6"), c.Flags.String("interface-prefix"), c.Flags.Bool("start"))
			if err != nil {
				return err
			}
			for _, route := range routes {
				logrus.Infof("Configured %s on %s for agent %d (%s)", route.Route, route.Interface, route.AgentID, route.Name)
			}
			return nil
		},
	})

	App.AddCommand(&grumble.Command{
		Name:      "chain_repair",
		Help:      "Preview or apply safe relay-chain repair actions",
		Usage:     "chain_repair [--interface-prefix ligolo] [--with-ipv6] [--start] [--prune-conflicts] [--apply]",
		HelpGroup: "Relay",
		Flags: func(f *grumble.Flags) {
			f.BoolL("with-ipv6", false, "Include IPv6 addresses")
			f.StringL("interface-prefix", "ligolo", "Interface name prefix for generated interface configs")
			f.BoolL("start", false, "Include or apply tunnel start actions")
			f.BoolL("prune-conflicts", false, "Remove configured lower-ranked duplicate routes")
			f.BoolL("apply", false, "Apply supported repair actions")
		},
		Run: func(c *grumble.Context) error {
			plan := chainRepairPlan(c.Flags.Bool("with-ipv6"), c.Flags.String("interface-prefix"), c.Flags.Bool("start"), c.Flags.Bool("prune-conflicts"))
			if c.Flags.Bool("apply") {
				plan = applyChainRepairPlan(c.Flags.Bool("with-ipv6"), c.Flags.String("interface-prefix"), c.Flags.Bool("start"), c.Flags.Bool("prune-conflicts"))
			}
			if len(plan.Actions) == 0 {
				App.Println("No repair actions pending.")
				return nil
			}

			t := table.NewWriter()
			t.SetStyle(table.StyleLight)
			t.SetTitle("Relay chain repair plan")
			t.AppendHeader(table.Row{"Type", "Agent ID", "Interface", "Route", "Supported", "Applied", "Reason", "Error"})
			for _, action := range plan.Actions {
				t.AppendRow(table.Row{action.Type, action.AgentID, action.Interface, action.Route, action.ApplySupported, action.Applied, action.Reason, action.Error})
			}
			App.Println(t.Render())
			return nil
		},
	})

	App.AddCommand(&grumble.Command{
		Name:      "chain_failover",
		Help:      "Show relay parent failover recommendations",
		Usage:     "chain_failover [--include-commands] [--apply] [--all] [--sessions session-a,session-b] [--agents 2,3]",
		HelpGroup: "Relay",
		Flags: func(f *grumble.Flags) {
			f.BoolL("include-commands", false, "Include downstream reconnect commands with relay tokens")
			f.BoolL("apply", false, "Apply selected failover recommendations")
			f.BoolL("all", false, "Apply every supported failover recommendation")
			f.StringL("sessions", "", "Comma-separated SessionIDs to fail over")
			f.StringL("agents", "", "Comma-separated agent IDs to fail over")
		},
		Run: func(c *grumble.Context) error {
			includeCommands := c.Flags.Bool("include-commands")
			plan := ChainFailoverPlan{}
			if c.Flags.Bool("apply") {
				sessionIDs := splitCSVStrings(c.Flags.String("sessions"))
				agentIDs, err := splitCSVInts(c.Flags.String("agents"))
				if err != nil {
					return err
				}
				if !c.Flags.Bool("all") && len(sessionIDs) == 0 && len(agentIDs) == 0 {
					return errors.New("chain_failover --apply requires --all, --sessions, or --agents")
				}
				plan = applyChainFailoverPlan(includeCommands, c.Flags.Bool("all"), sessionIDs, agentIDs)
			} else {
				plan = chainFailoverPlan(includeCommands)
			}
			if len(plan.Recommendations) == 0 {
				App.Println("No failover recommendations.")
				return nil
			}

			t := table.NewWriter()
			t.SetStyle(table.StyleLight)
			t.SetTitle("Relay parent failover plan")
			header := table.Row{"Agent ID", "Agent", "Current Parent", "Recommended Parent", "Apply", "Applied", "Reason", "Error"}
			if includeCommands {
				header = append(header, "Connect Command")
			}
			t.AppendHeader(header)
			for _, recommendation := range plan.Recommendations {
				recommendedParent := "-"
				if recommendation.RecommendedParent != nil {
					recommendedParent = fmt.Sprintf("%d - %s", recommendation.RecommendedParent.AgentID, recommendation.RecommendedParent.Name)
				}
				row := table.Row{recommendation.AgentID, recommendation.Name, recommendation.CurrentParentName, recommendedParent, recommendation.ApplySupported, recommendation.Applied, recommendation.Reason, recommendation.Error}
				if includeCommands {
					row = append(row, recommendation.ConnectCommand)
				}
				t.AppendRow(row)
			}
			App.Println(t.Render())
			return nil
		},
	})
}

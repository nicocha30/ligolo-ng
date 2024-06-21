package app

import (
	"errors"
	"github.com/desertbit/grumble"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/nicocha30/ligolo-ng/pkg/proxy/netstack/tun"
	"github.com/nicocha30/ligolo-ng/pkg/utils/codenames"
	"github.com/sirupsen/logrus"
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

			AgentListMutex.Lock()
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
			AgentListMutex.Unlock()
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

				ifName = codenames.Generate(rng, 0)
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
				return errors.New("please specify a route")
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

}

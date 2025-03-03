package config

import (
	"fmt"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/nicocha30/ligolo-ng/pkg/proxy/netinfo"
	"slices"
	"strings"
)

// interface.name config
type InterfaceConfig struct {
	Routes []string
}

type InterfaceRoute struct {
	Destination string
	Active      bool
}

type InterfaceInfo struct {
	Routes []InterfaceRoute
	Active bool
}

func (i *InterfaceInfo) GetStateString() string {
	var activeRoutes, pendingRoutes int
	var stringBuffer []string
	for _, route := range i.Routes {
		if route.Active {
			activeRoutes++
		} else {
			pendingRoutes++
		}
	}
	if activeRoutes > 0 {
		stringBuffer = append(stringBuffer, text.Colors{text.FgGreen}.Sprintf("Active - %d routes", activeRoutes))
	}
	if pendingRoutes > 0 {
		stringBuffer = append(stringBuffer, text.Colors{text.FgYellow}.Sprintf("Pending - %d routes", pendingRoutes))
	}
	return strings.Join(stringBuffer, " / ")

}

func (i *InterfaceInfo) GetRoutes() (routes []string) {
	for _, route := range i.Routes {
		routes = append(routes, route.Destination)
	}
	return
}

func (i *InterfaceInfo) IsRouteActive(route string) bool {
	for _, routeRoute := range i.Routes {
		if routeRoute.Destination == route {
			return true
		}
	}
	return false
}

func (i *InterfaceInfo) GetRouteString() string {
	var stringBuffer []string
	for _, route := range i.Routes {
		if route.Active {
			stringBuffer = append(stringBuffer, text.Colors{text.FgGreen}.Sprintf(route.Destination))
		} else {
			stringBuffer = append(stringBuffer, text.Colors{text.FgYellow}.Sprintf(route.Destination))
		}
	}
	return strings.Join(stringBuffer, ",")
}

func GetInterfaceConfigState() (map[string]InterfaceInfo, error) {
	tuntaps, err := netinfo.GetTunTaps()
	if err != nil {
		return nil, err
	}

	interfaces := make(map[string]InterfaceInfo)
	// Read currently existing tuntaps on the system
	for _, tuntap := range tuntaps {
		ifInfo := InterfaceInfo{
			Active: true,
		}
		for _, route := range tuntap.Routes() {
			ifInfo.Routes = append(ifInfo.Routes, InterfaceRoute{
				Destination: route.Dst,
				Active:      true,
			})
		}
		interfaces[tuntap.Name()] = ifInfo
	}

	// Read interfaces from the configuration file
	var ifaceInfo map[string]InterfaceConfig
	Config.UnmarshalKey("interface", &ifaceInfo)

	for ifaceName, pendingTaps := range ifaceInfo {
		ifInfo := InterfaceInfo{
			Active: false,
		}
		// If interface already exist, but has pending routes
		if cInterface, ok := interfaces[ifaceName]; ok {
			ifInfo = cInterface
		}

		for _, route := range pendingTaps.Routes {
			if !ifInfo.IsRouteActive(route) {
				ifInfo.Routes = append(ifInfo.Routes, InterfaceRoute{
					Destination: route,
					Active:      false,
				})
			}
		}
		interfaces[ifaceName] = ifInfo
	}
	return interfaces, nil
}

func AddRouteConfig(ifName string, routeCidr string) error {
	// Get current iface config
	configPath := fmt.Sprintf("interface.%s.routes", ifName)
	currentRoutes := Config.GetStringSlice(configPath)
	if slices.Contains(currentRoutes, routeCidr) {
		// Route already exists
		return nil
	}
	// Add route to config
	currentRoutes = append(currentRoutes, routeCidr)
	Config.Set(configPath, currentRoutes)
	// Save config
	if err := Config.WriteConfig(); err != nil {
		return err
	}
	return nil
}

func DeleteRouteConfig(ifName string, routeCidr string) error {
	configPath := fmt.Sprintf("interface.%s.routes", ifName)
	currentRoutes := Config.GetStringSlice(configPath)
	var newRoutes []string
	for _, route := range currentRoutes {
		if route != routeCidr {
			newRoutes = append(newRoutes, route)
		}
	}
	Config.Set(configPath, newRoutes)
	if err := Config.WriteConfig(); err != nil {
		return err
	}
	return nil
}

func AddInterfaceConfig(ifName string) error {
	var ifaceInfo map[string]InterfaceConfig
	// Unmarshal current interfaces config
	Config.UnmarshalKey("interface", &ifaceInfo)
	// Add an entry
	ifaceInfo[ifName] = InterfaceConfig{
		Routes: nil,
	}
	// Update the config
	Config.Set("interface", ifaceInfo)
	if err := Config.WriteConfig(); err != nil {
		return err
	}
	return nil
}

func GetInterfaceRoutesConfig(ifName string) []string {
	configPath := fmt.Sprintf("interface.%s.routes", ifName)
	return Config.GetStringSlice(configPath)
}

func DeleteInterfaceConfig(ifName string) error {
	var ifaceInfo map[string]InterfaceConfig
	Config.UnmarshalKey("interface", &ifaceInfo)
	delete(ifaceInfo, ifName)
	Config.Set("interface", ifaceInfo)
	if err := Config.WriteConfig(); err != nil {
		return err
	}
	return nil
}

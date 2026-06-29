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

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"strings"
	"syscall"

	"github.com/allsmog/ligolo-ng-relay/cmd/proxy/app"
	"github.com/allsmog/ligolo-ng-relay/cmd/proxy/config"
	"github.com/allsmog/ligolo-ng-relay/pkg/controller"
	"github.com/allsmog/ligolo-ng-relay/pkg/tlsutils"
	"github.com/desertbit/grumble"
	"github.com/hashicorp/yamux"
	"github.com/sirupsen/logrus"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	var allowDomains []string
	var verboseFlag = flag.Bool("v", false, "enable verbose mode")
	var listenInterface = flag.String("laddr", "0.0.0.0:11601", "listening address (prefix with http(s):// for websocket)")
	var enableAutocert = flag.Bool("autocert", false, "automatically request letsencrypt certificates, requires port 80 to be accessible")
	var enableSelfcert = flag.Bool("selfcert", false, "dynamically generate self-signed certificates")
	var certFile = flag.String("certfile", "certs/cert.pem", "TLS server certificate")
	var keyFile = flag.String("keyfile", "certs/key.pem", "TLS server key")
	var domainWhitelist = flag.String("allow-domains", "", "autocert authorised domains, if empty, allow all domains, multiple domains should be comma-separated.")
	var selfcertDomain = flag.String("selfcert-domain", "ligolo", "The selfcert TLS domain to use")
	var versionFlag = flag.Bool("version", false, "show the current version")
	var hideBanner = flag.Bool("nobanner", false, "don't show banner on startup")
	var configFile = flag.String("config", "", "the config file to use")
	var daemonMode = flag.Bool("daemon", false, "run as daemon mode (no CLI)")
	var apiEnabled = flag.Bool("api", false, "enable the Web/API server without editing the config file")
	var apiListenAddr = flag.String("api-laddr", "", "API server listening address (default: 127.0.0.1:8080)")
	var webDisableUI = flag.Bool("no-web-ui", false, "disable the embedded Web UI while keeping the API server available")
	var relayAutoHeal = flag.Bool("relay-autoheal", false, "enable the relay auto-heal reconciler")
	var relayAutoHealApply = flag.Bool("relay-autoheal-apply", false, "allow relay auto-heal to apply supported repairs and failovers")
	var mcpStdio = flag.Bool("mcp", false, "run an MCP server over stdio (headless; the proxy still listens for agents)")
	var mcpReadOnly = flag.Bool("mcp-read-only", false, "expose only read-only MCP tools (applies to -mcp and -mcp-api)")
	var mcpAPI = flag.Bool("mcp-api", false, "mount the MCP server over streamable HTTP at /mcp on the API server (implies -api)")
	var webUser string
	var webPassword string
	var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to `file`")
	var memprofile = flag.String("memprofile", "", "write memory profile to `file`")
	flag.StringVar(&webUser, "web-user", "", "Web/API username override")
	flag.StringVar(&webUser, "api-user", "", "alias for -web-user")
	flag.StringVar(&webPassword, "web-password", "", "Web/API password override")
	flag.StringVar(&webPassword, "api-password", "", "alias for -web-password")

	flag.Usage = func() {
		fmt.Printf("Ligolo-ng Relay %s / %s / %s\n", version, commit, date)
		fmt.Println("Maintained fork of upstream Ligolo-ng by @Nicocha30")
		fmt.Println("https://github.com/allsmog/ligolo-ng-relay")
		fmt.Printf("\nUsage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal("could not create CPU profile: ", err)
		}
		defer f.Close() // error handling omitted for example
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("could not start CPU profile: ", err)
		}
		defer pprof.StopCPUProfile()
	}

	app.MCPServerVersion = version
	headless := *daemonMode || *mcpStdio
	config.InitConfig(*configFile, headless)

	if *apiEnabled {
		config.Config.Set("web.enabled", true)
	}
	if *apiListenAddr != "" {
		config.Config.Set("web.listen", *apiListenAddr)
	}
	if *webDisableUI {
		config.Config.Set("web.enableui", false)
	}
	if *relayAutoHeal {
		config.Config.Set("relay.autoheal.enabled", true)
	}
	if *relayAutoHealApply {
		config.Config.Set("relay.autoheal.enabled", true)
		config.Config.Set("relay.autoheal.apply", true)
	}
	if webUser != "" || webPassword != "" {
		if webUser == "" || webPassword == "" {
			logrus.Fatal("both -web-user and -web-password must be set")
		}
		if err := config.SetWebUserPassword(webUser, webPassword); err != nil {
			logrus.Fatal(err)
		}
	}
	if *mcpAPI {
		config.Config.Set("web.enabled", true)
		config.Config.Set("web.mcp", true)
	}
	config.Config.Set("web.mcpreadonly", *mcpReadOnly)

	if *versionFlag {
		fmt.Printf("Ligolo-ng Relay %s / %s / %s\n", version, commit, date)
		return
	}

	if *verboseFlag {
		logrus.SetLevel(logrus.DebugLevel)
	}

	// If verbose is set, include method and line in log messages
	logrus.SetReportCaller(*verboseFlag)

	if *domainWhitelist != "" {
		allowDomains = strings.Split(*domainWhitelist, ",")
	}

	if !*hideBanner && !headless {
		app.App.SetPrintASCIILogo(func(a *grumble.App) {
			a.Println("    __    _             __                       ")
			a.Println("   / /   (_)___ _____  / /___        ____  ____ _")
			a.Println("  / /   / / __ `/ __ \\/ / __ \\______/ __ \\/ __ `/")
			a.Println(" / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ / ")
			a.Println("/_____/_/\\__, /\\____/_/\\____/     /_/ /_/\\__, /  ")
			a.Println("        /____/                          /____/   ")
			a.Println("\n  Made in France ♥            by @Nicocha30!")
			a.Printf("  Version: %s\n\n", version)
		})
	}

	if *enableSelfcert && *selfcertDomain == "ligolo" {
		logrus.Warning("Using default selfcert domain 'ligolo', beware of CTI, SOC and IoC!")
	}

	app.Run()

	proxyController := controller.New(controller.ControllerConfig{
		Address: *listenInterface,
		CertManagerConfig: &tlsutils.CertManagerConfig{
			SelfCertCache:   "ligolo-selfcerts",
			Certfile:        *certFile,
			Keyfile:         *keyFile,
			DomainWhitelist: allowDomains,
			SelfcertDomain:  *selfcertDomain,
			EnableAutocert:  *enableAutocert,
			EnableSelfcert:  *enableSelfcert,
		},
	})

	app.ProxyController = &proxyController

	go proxyController.ListenAndServe()

	// Wait for listener
	if err := proxyController.WaitForReady(); err != nil {
		logrus.Fatal(err)
	}

	// Agent registration goroutine
	go func() {
		for {
			remoteConn := <-proxyController.Connection

			yamuxConn, err := yamux.Client(remoteConn, nil)
			if err != nil {
				logrus.Errorf("could not create yamux client, error: %v", err)
				continue
			}

			agent, err := controller.NewAgent(yamuxConn)
			if err != nil {
				logrus.Errorf("could not register agent, error: %v", err)
				continue
			}

			logrus.WithFields(logrus.Fields{"remote": remoteConn.RemoteAddr(), "name": agent.Name, "id": agent.SessionID}).Info("Agent joined.")

			if err := app.RegisterAgent(agent); err != nil {
				logrus.Errorf("could not register agent: %s", err.Error())
			}

			go func() {
				// Check agent status
				for {
					select {
					case <-agent.Session.CloseChan(): // Agent closed
						app.ChainMgr.RemoveAgent(agent.SessionID)
						logrus.WithFields(logrus.Fields{"remote": remoteConn.RemoteAddr(), "name": agent.Name, "id": agent.SessionID}).Warnf("Agent dropped.")
						return
					}
				}
			}()

		}
	}()

	if *daemonMode && !config.Config.GetBool("web.enabled") {
		logrus.Warning("daemon mode enabled but web.enabled is false!")
	}

	if config.Config.GetBool("web.enabled") {
		logrus.Infof("Starting Ligolo-ng Relay Web, API URL is set to: %s", app.GetAPIUrl())
		go app.StartLigoloApi()
	}
	app.StartRelayAutoHealFromConfig()

	if *mcpStdio {
		// MCP-over-stdio is the operator frontend; the proxy keeps serving
		// agents in the background. stdout carries the MCP stream, so logs
		// (logrus) must stay on stderr and the banner is suppressed (headless).
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := app.RunMCPStdio(ctx, *mcpReadOnly); err != nil && !errors.Is(err, context.Canceled) {
			logrus.Fatal(err)
		}
	} else if *daemonMode {
		proxyController.WaitForFinished()
	} else {
		// Grumble doesn't like cli args
		os.Args = []string{}
		grumble.Main(app.App)
	}

	if *memprofile != "" {
		f, err := os.Create(*memprofile)
		if err != nil {
			log.Fatal("could not create memory profile: ", err)
		}
		defer f.Close()
		runtime.GC()
		if err := pprof.Lookup("allocs").WriteTo(f, 0); err != nil {
			log.Fatal("could not write memory profile: ", err)
		}
	}

}

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/desertbit/grumble"
	"github.com/hashicorp/yamux"
	"github.com/nicocha30/ligolo-ng/cmd/proxy/app"
	"github.com/nicocha30/ligolo-ng/pkg/controller"
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
	var listenInterface = flag.String("laddr", "0.0.0.0:11601", "listening address (prefix with https:// for websocket)")
	var enableAutocert = flag.Bool("autocert", false, "automatically request letsencrypt certificates, requires port 80 to be accessible")
	var enableSelfcert = flag.Bool("selfcert", false, "dynamically generate self-signed certificates")
	var certFile = flag.String("certfile", "certs/cert.pem", "TLS server certificate")
	var keyFile = flag.String("keyfile", "certs/key.pem", "TLS server key")
	var domainWhitelist = flag.String("allow-domains", "", "autocert authorised domains, if empty, allow all domains, multiple domains should be comma-separated.")
	var selfcertDomain = flag.String("selfcert-domain", "ligolo", "The selfcert TLS domain to use")
	var versionFlag = flag.Bool("version", false, "show the current version")

	flag.Usage = func() {
		fmt.Printf("Ligolo-ng %s / %s / %s\n", version, commit, date)
		fmt.Println("Made in France with love by @Nicocha30!")
		fmt.Println("https://github.com/nicocha30/ligolo-ng")
		fmt.Printf("\nUsage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if *versionFlag {
		fmt.Printf("Ligolo-ng %s / %s / %s\n", version, commit, date)
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

	if *enableSelfcert && *selfcertDomain == "ligolo" {
		logrus.Warning("Using default selfcert domain 'ligolo', beware of CTI, SOC and IoC!")
	}

	app.Run()

	proxyController := controller.New(controller.ControllerConfig{
		EnableAutocert:  *enableAutocert,
		EnableSelfcert:  *enableSelfcert,
		Address:         *listenInterface,
		Certfile:        *certFile,
		Keyfile:         *keyFile,
		DomainWhitelist: allowDomains,
		SelfcertDomain:  *selfcertDomain,
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
						logrus.WithFields(logrus.Fields{"remote": remoteConn.RemoteAddr(), "name": agent.Name, "id": agent.SessionID}).Warnf("Agent dropped.")
						return
					}
				}
			}()

		}
	}()

	// Grumble doesn't like cli args
	os.Args = []string{}
	grumble.Main(app.App)
}

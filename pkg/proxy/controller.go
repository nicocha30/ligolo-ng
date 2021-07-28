package proxy

import (
	"crypto/tls"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme/autocert"
	"net"
	"net/http"
)

type Controller struct {
	Network    string
	Connection chan net.Conn
	startchan  chan interface{}
	ControllerConfig
}

type ControllerConfig struct {
	EnableAutocert  bool
	Address         string
	Certfile        string
	Keyfile         string
	DomainWhitelist []string
}

func New(config ControllerConfig) Controller {
	return Controller{Network: "tcp", Connection: make(chan net.Conn, 1024), ControllerConfig: config, startchan: make(chan interface{})}
}

func (c *Controller) WaitForReady() {
	<-c.startchan
	return
}

func (c *Controller) ListenAndServe() {
	var tlsConfig tls.Config

	if c.EnableAutocert {
		// Enable letsencrypt
		certManager := autocert.Manager{
			Prompt: autocert.AcceptTOS,
			Cache:  autocert.DirCache("ligolo-certs"),
		}
		if len(c.DomainWhitelist) > 0 {
			certManager.HostPolicy = autocert.HostWhitelist(c.DomainWhitelist...)
		}
		tlsConfig.GetCertificate = certManager.GetCertificate
		go func() {
			h := certManager.HTTPHandler(nil)
			logrus.Fatal(http.ListenAndServe(":http", h))
		}()
	} else {
		if c.Certfile != "" && c.Keyfile != "" {
			cer, err := tls.LoadX509KeyPair(c.Certfile, c.Keyfile)
			if err != nil {
				logrus.WithFields(logrus.Fields{"certfile": c.Certfile, "keyfile": c.Keyfile}).Fatal("Could not load TLS certificate.")
			}
			tlsConfig.Certificates = []tls.Certificate{cer}
		}
	}

	listener, err := tls.Listen(c.Network, c.Address, &tlsConfig)
	if err != nil {
		logrus.Fatal(err)
	}
	defer listener.Close()
	close(c.startchan) // Controller is listening.
	logrus.Infof("Listening on %s", c.Address)
	for {
		conn, err := listener.Accept()
		if err != nil {
			logrus.Error(err)
			continue
		}
		c.Connection <- conn
	}
}

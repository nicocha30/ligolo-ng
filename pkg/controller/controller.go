package controller

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"github.com/nicocha30/ligolo-ng/pkg/utils/selfcert"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme/autocert"
	"net"
	"net/http"
	"nhooyr.io/websocket"
	"strings"
	"time"
)

type Controller struct {
	Network       string
	Connection    chan net.Conn
	startchan     chan error
	SelfCertCache autocert.DirCache
	SelfCert      *tls.Certificate
	ControllerConfig
}

type ControllerConfig struct {
	EnableAutocert  bool
	EnableSelfcert  bool
	SelfcertDomain  string
	Address         string
	Certfile        string
	Keyfile         string
	DomainWhitelist []string
}

var wsconn net.Conn

func New(config ControllerConfig) Controller {
	return Controller{Network: "tcp", Connection: make(chan net.Conn, 1024), ControllerConfig: config, startchan: make(chan error), SelfCertCache: "ligolo-selfcerts"}
}

type ligoloHttpServer struct {
	// logf controls where logs are sent.
	logf func(f string, v ...interface{})
}

func (s ligoloHttpServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		logrus.Error(err)
		return
	}
	netctx, _ := context.WithTimeout(context.Background(), time.Hour*999999)
	wsconn = websocket.NetConn(netctx, c, websocket.MessageBinary)
	return
}

func (c *Controller) WaitForReady() error {
	return <-c.startchan
}

func (c *Controller) ListenAndServe() {
	var tlsConfig tls.Config

	if c.EnableAutocert {
		// Enable letsencrypt
		logrus.Info("Using Let's Encrypt ACME Autocert")
		certManager := autocert.Manager{
			Prompt: autocert.AcceptTOS,
			Cache:  autocert.DirCache("ligolo-certs"),
		}
		if len(c.DomainWhitelist) > 0 {
			certManager.HostPolicy = autocert.HostWhitelist(c.DomainWhitelist...)
		}
		tlsConfig.GetCertificate = certManager.GetCertificate

		// Check if port 80 is available
		lis, err := net.Listen("tcp", ":http")
		if err != nil {
			c.startchan <- errors.New("Port 80 is not available, please make sure it's accessible for Let's Encrypt ACME challenge")
			return
		}
		lis.Close()

		go func() {
			h := certManager.HTTPHandler(nil)
			http.ListenAndServe(":http", h)
		}()
	} else if c.EnableSelfcert {
		logrus.Warning("Using self-signed certificates")
		selfcrt := selfcert.NewSelfCert(&c.SelfCertCache)
		crt, err := selfcrt.GetCertificate(c.SelfcertDomain)
		if err != nil {
			logrus.Fatal(err)
		}
		logrus.Warnf("TLS Certificate fingerprint for %s is: %X\n", c.SelfcertDomain, sha256.Sum256(crt.Certificate[0]))
		c.SelfCert = crt
		tlsConfig.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return crt, nil
		}

	} else if c.Certfile != "" && c.Keyfile != "" {
		cer, err := tls.LoadX509KeyPair(c.Certfile, c.Keyfile)
		if err != nil {
			logrus.WithFields(logrus.Fields{"certfile": c.Certfile, "keyfile": c.Keyfile}).Error("Could not load TLS certificate. Please make sure paths are correct or use -autocert or -selfcert options")
			c.startchan <- err
			return
		}
		tlsConfig.Certificates = []tls.Certificate{cer}
	} else {
		c.startchan <- errors.New("No valid TLS configuration found, please use -certfile/-keyfile, -autocert or -selfcert options")
		return
	}

	if strings.Contains(c.Address, "https://") {
		//SSL websocket protocol
		listener, err := tls.Listen(c.Network, strings.Replace(c.Address, "https://", "", 1), &tlsConfig)
		if err != nil {
			logrus.Fatal(err)
		}
		defer listener.Close()
		close(c.startchan) // Controller is listening.
		logrus.Infof("Listening websocket on %s", c.Address)

		s := &http.Server{
			Handler: ligoloHttpServer{},
		}
		for {
			//start http handler in go routine
			go func() {
				err = s.Serve(listener)
			}()
			if err != nil {
				logrus.Error(err)
			}
			//manual waiting until handler got connection and global variable wsconn is set by http handler
			//this not so gracefully but effective ))
			for {
				if wsconn != nil {
					logrus.Debugf("Got websocket connection %s", wsconn.RemoteAddr())
					c.Connection <- wsconn
					wsconn = nil
					break
				}
				//add some sleep to reduce CPU usage, because it is in loop
				time.Sleep(time.Millisecond * 500)
			}
		}
	} else {
		//direct listen with legacy ligolo-ng protocol
		listener, err := tls.Listen(c.Network, c.Address, &tlsConfig)
		if err != nil {
			c.startchan <- err
			return
		}
		defer listener.Close()
		c.startchan <- nil // Controller is listening.
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
}

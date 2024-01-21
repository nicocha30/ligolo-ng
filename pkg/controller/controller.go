package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme/autocert"
	"math/big"
	"net"
	"net/http"
	"nhooyr.io/websocket"
	"strings"
	"sync"
	"time"
)

type Controller struct {
	Network          string
	Connection       chan net.Conn
	startchan        chan interface{}
	certificateMap   map[string]*tls.Certificate
	certificateMutex sync.Mutex
	ControllerConfig
}

type ControllerConfig struct {
	EnableAutocert  bool
	EnableSelfcert  bool
	Address         string
	Certfile        string
	Keyfile         string
	DomainWhitelist []string
}

var wsconn net.Conn

func New(config ControllerConfig) Controller {
	return Controller{Network: "tcp", Connection: make(chan net.Conn, 1024), ControllerConfig: config, startchan: make(chan interface{}), certificateMap: make(map[string]*tls.Certificate)}
}

func (c *Controller) WaitForReady() {
	<-c.startchan
	return
}

type myHttpServer struct {
	// logf controls where logs are sent.
	logf func(f string, v ...interface{})
}

func (s myHttpServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		logrus.Error(err)
		return
	}
	netctx, _ := context.WithTimeout(context.Background(), time.Hour*999999)
	wsconn = websocket.NetConn(netctx, c, websocket.MessageBinary)
	return
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
		go func() {
			h := certManager.HTTPHandler(nil)
			logrus.Fatal(http.ListenAndServe(":http", h))
		}()
	} else if c.EnableSelfcert {
		logrus.Warning("Using automatically generated self-signed certificates (Not recommended)")

		tlsConfig.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// Cache
			c.certificateMutex.Lock()
			if cert, ok := c.certificateMap[info.ServerName]; ok {
				c.certificateMutex.Unlock()
				return cert, nil
			}
			c.certificateMutex.Unlock()
			priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				logrus.Fatal(err)
			}

			serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
			serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
			if err != nil {
				return nil, err
			}

			template := x509.Certificate{
				SerialNumber: serialNumber,
				Subject: pkix.Name{
					Organization: []string{info.ServerName},
				},
				NotBefore: time.Now(),
				NotAfter:  time.Now().Add(time.Hour * 24 * 365),

				KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
				ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				BasicConstraintsValid: true,
			}

			if info.ServerName != "" {
				template.DNSNames = []string{info.ServerName}
			}

			derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)

			if err != nil {
				return nil, err
			}
			finalCert := &tls.Certificate{
				Certificate: [][]byte{derBytes},
				PrivateKey:  priv,
			}
			// Cache!
			c.certificateMutex.Lock()
			c.certificateMap[info.ServerName] = finalCert
			c.certificateMutex.Unlock()
			return finalCert, nil

		}
	} else if c.Certfile != "" && c.Keyfile != "" {
		cer, err := tls.LoadX509KeyPair(c.Certfile, c.Keyfile)
		if err != nil {
			logrus.WithFields(logrus.Fields{"certfile": c.Certfile, "keyfile": c.Keyfile}).Fatal("Could not load TLS certificate. Please make sure paths are correct or use -autocert or -selfcert options")
		}
		tlsConfig.Certificates = []tls.Certificate{cer}
	} else {
		logrus.Fatal("No valid TLS configuration found, please use -certfile/-keyfile, -autocert or -selfcert options")
	}

	if strings.Contains(c.Address, "https://") {
		//websocket https listen
		listener, err := tls.Listen(c.Network, strings.Replace(c.Address, "https://", "", 1), &tlsConfig)
		if err != nil {
			logrus.Fatal(err)
		}
		defer listener.Close()
		close(c.startchan) // Controller is listening.
		logrus.Infof("Listening websocket on %s", c.Address)

		s := &http.Server{
			Handler: myHttpServer{},
		}
		for {
			go func() {
				err = s.Serve(listener)
			}()
			if err != nil {
				logrus.Error(err)
			}
			//manual waiting until handler got connection and set wsconn variable
			for {
				if wsconn != nil {
					logrus.Infof("Got websocket connection %s", wsconn.RemoteAddr())
					c.Connection <- wsconn
					wsconn = nil
					break
				}
				time.Sleep(time.Millisecond * 500)
			}
		}
	} else if strings.Contains(c.Address, "http://") {
		//websocket http listen
		listener, err := net.Listen(c.Network, strings.Replace(c.Address, "http://", "", 1))
		if err != nil {
			logrus.Fatal(err)
		}
		defer listener.Close()
		close(c.startchan) // Controller is listening.
		logrus.Infof("Listening websocket on %s", c.Address)

		s := &http.Server{
			Handler: myHttpServer{},
		}
		for {
			go func() {
				err = s.Serve(listener)
			}()
			if err != nil {
				logrus.Error(err)
			}
			//manual waiting until handler got connection and set wsconn variable
			for {
				if wsconn != nil {
					logrus.Infof("Got websocket connection %s", wsconn.RemoteAddr())
					c.Connection <- wsconn
					wsconn = nil
					break
				}
				time.Sleep(time.Millisecond * 500)
			}
		}
	} else {
		//direct listen
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
}

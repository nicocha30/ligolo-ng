package controller

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme/autocert"
)

type Controller struct {
	Network          string
	Connection       chan net.Conn
	startchan        chan error
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

func New(config ControllerConfig) Controller {
	return Controller{Network: "tcp", Connection: make(chan net.Conn, 1024), ControllerConfig: config, startchan: make(chan error), certificateMap: make(map[string]*tls.Certificate)}
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
				return nil, err
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
			logrus.WithFields(logrus.Fields{"certfile": c.Certfile, "keyfile": c.Keyfile}).Error("Could not load TLS certificate. Please make sure paths are correct or use -autocert or -selfcert options")
			c.startchan <- err
			return
		}
		tlsConfig.Certificates = []tls.Certificate{cer}
	} else {
		c.startchan <- errors.New("No valid TLS configuration found, please use -certfile/-keyfile, -autocert or -selfcert options")
		return
	}

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

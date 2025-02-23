package tlsutils

import (
	"crypto/tls"
	"errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme/autocert"
	"net"
	"net/http"
)

type CertManagerConfig struct {
	EnableAutocert  bool
	DomainWhitelist []string
	EnableSelfcert  bool
	SelfCertCache   autocert.DirCache
	SelfcertDomain  string
	Certfile        string
	Keyfile         string
}

var acmeHandlerStarted bool

func CertManager(c *CertManagerConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{}
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

		if !acmeHandlerStarted {
			// Check if port 80 is available
			lis, err := net.Listen("tcp", ":http")
			if err != nil {
				return nil, errors.New("Port 80 is not available, please make sure it's accessible for Let's Encrypt ACME challenge")
			}
			lis.Close()

			go func() {
				h := certManager.HTTPHandler(nil)
				http.ListenAndServe(":http", h)
			}()
			acmeHandlerStarted = true
		}
	} else if c.EnableSelfcert {
		selfcrt := NewSelfCert(&c.SelfCertCache)
		crt, err := selfcrt.GetCertificate(c.SelfcertDomain)
		if err != nil {
			logrus.Fatal(err)
		}
		tlsConfig.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return crt, nil
		}

	} else if c.Certfile != "" && c.Keyfile != "" {
		cer, err := tls.LoadX509KeyPair(c.Certfile, c.Keyfile)
		if err != nil {
			logrus.WithFields(logrus.Fields{"certfile": c.Certfile, "keyfile": c.Keyfile}).Error("Could not load TLS certificate. Please make sure paths are correct or use -autocert or -selfcert options")
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cer}
	} else {
		return nil, errors.New("No valid TLS configuration found, please use -certfile/-keyfile, -autocert or -selfcert options")
	}
	return tlsConfig, nil
}

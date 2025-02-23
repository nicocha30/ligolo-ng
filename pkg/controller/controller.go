package controller

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/nicocha30/ligolo-ng/pkg/tlsutils"
	"github.com/sirupsen/logrus"
	"net"
	"net/http"
	"nhooyr.io/websocket"
	"strings"
)

type Controller struct {
	Network    string
	Connection chan net.Conn
	startchan  chan error
	ControllerConfig
}

type ControllerConfig struct {
	Address           string
	CertManagerConfig *tlsutils.CertManagerConfig
	tlsConfig         *tls.Config
}

func New(config ControllerConfig) Controller {
	return Controller{Network: "tcp", Connection: make(chan net.Conn, 1024), ControllerConfig: config, startchan: make(chan error)}
}

func (c *Controller) WaitForReady() error {
	return <-c.startchan
}

func (c *Controller) GetSelfCertificateSignature() (*tls.Certificate, error) {
	if c.CertManagerConfig.EnableSelfcert {
		return c.tlsConfig.GetCertificate(nil)
	}
	return nil, errors.New("selfcert is not enabled")
}

func (c *Controller) ListenAndServe() {
	tlsConfig, err := tlsutils.CertManager(c.CertManagerConfig)
	if err != nil {
		c.startchan <- err
	}
	c.tlsConfig = tlsConfig

	if strings.HasPrefix(c.Address, "https://") {
		//SSL websocket protocol
		listener, err := tls.Listen(c.Network, strings.Replace(c.Address, "https://", "", 1), c.tlsConfig)
		if err != nil {
			c.startchan <- err
			return
		}
		defer listener.Close()

		c.startchan <- nil
		logrus.Infof("Listening websocket on %s", c.Address)

		s := &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ws, err := websocket.Accept(w, r, nil)
				if err != nil {
					logrus.Error(err)
					return
				}
				netctx := context.Background()

				c.Connection <- websocket.NetConn(netctx, ws, websocket.MessageBinary)
			}),
		}
		err = s.Serve(listener)
	} else {
		//direct listen with legacy ligolo-ng protocol
		listener, err := tls.Listen(c.Network, c.Address, c.tlsConfig)
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

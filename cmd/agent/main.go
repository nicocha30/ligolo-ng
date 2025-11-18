// Ligolo-ng
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
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/nicocha30/ligolo-ng/pkg/tlsutils"
	"github.com/nicocha30/ligolo-ng/pkg/utils"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/nicocha30/ligolo-ng/pkg/agent"
	"github.com/sirupsen/logrus"
	goproxy "golang.org/x/net/proxy"
	"nhooyr.io/websocket"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	var tlsConfig tls.Config
	var ignoreCertificate = flag.Bool("ignore-cert", false, "ignore TLS certificate validation (dangerous), only for debug purposes")
	var acceptFingerprint = flag.String("accept-fingerprint", "", "accept certificates matching the following SHA256 fingerprint (hex format)")
	var verbose = flag.Bool("v", false, "enable verbose mode")
	var retry = flag.Bool("retry", false, "auto-retry on error")
	var socksProxy = flag.String("proxy", "", "proxy URL address (http://admin:secret@127.0.0.1:8080)"+
		" or socks://admin:secret@127.0.0.1:8080")
	var serverAddr = flag.String("connect", "", "connect to proxy (domain:port)")
	var bindAddr = flag.String("bind", "", "bind to ip:port")
	var userAgent = flag.String("ua", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "+
		"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36", "HTTP User-Agent")
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

	logrus.SetReportCaller(*verbose)

	if *verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}

	if *bindAddr != "" {
		bind(&tlsConfig, *bindAddr)
	}

	if *serverAddr == "" {
		logrus.Fatal("please, specify the target host user -connect host:port")
	}

	ligoloUrl, err := utils.ParseLigoloURL(*serverAddr)
	if err != nil {
		logrus.Fatalf("Invalid connect address, please use http(s)://host:port for websocket or host:port for tcp")
	}

	tlsConfig.ServerName = ligoloUrl.Hostname()

	if *ignoreCertificate {
		logrus.Warn("warning, certificate validation disabled")
		tlsConfig.InsecureSkipVerify = true
	}

	var conn net.Conn

	for {
		var err error
		if ligoloUrl.IsWebsocket() {
			//websocket
			err = wsconnect(&tlsConfig, *serverAddr, *socksProxy, *userAgent)
		} else {
			if *socksProxy != "" {
				//suppose that scheme is socks:// or socks5://
				var proxyUrl *url.URL
				proxyUrl, err = url.Parse(*socksProxy)
				if err != nil {
					logrus.Fatal("invalid proxy address, please use socks5://host:port")
				}
				if proxyUrl.Scheme == "http" {
					logrus.Fatal("Can't use http-proxy with direct (tcp) connection. Only with websocket")
				}
				if proxyUrl.Scheme == "socks" || proxyUrl.Scheme == "socks5" {
					pass, _ := proxyUrl.User.Password()
					conn, err = sockDial(*serverAddr, proxyUrl.Host, proxyUrl.User.Username(), pass)
				} else {
					logrus.Fatal("invalid socks5 address, please use socks://host:port")
				}
			} else {
				conn, err = net.Dial("tcp", *serverAddr)
			}
			if err == nil {
				if *acceptFingerprint != "" {
					tlsConfig.InsecureSkipVerify = true
					tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
						crtFingerprint := sha256.Sum256(rawCerts[0])
						crtMatch, err := hex.DecodeString(*acceptFingerprint)
						if err != nil {
							return fmt.Errorf("invalid cert fingerprint: %v\n", err)
						}
						if bytes.Compare(crtMatch, crtFingerprint[:]) != 0 {
							return fmt.Errorf("certificate does not match fingerprint: %X != %X", crtFingerprint, crtMatch)
						}
						return nil
					}
				}
				tlsConn := tls.Client(conn, &tlsConfig)
				err = connect(tlsConn)
			}

		}

		logrus.Errorf("Connection error: %v", err)
		if *retry {
			logrus.Info("Retrying in 5 seconds.")
			time.Sleep(5 * time.Second)
		} else {
			logrus.Fatal(err)
		}
	}
}

// sockDial is used when connecting using direct connection through a socks5 proxy server.
func sockDial(serverAddr string, socksProxy string, socksUser string, socksPass string) (net.Conn, error) {
	proxyDialer, err := goproxy.SOCKS5("tcp", socksProxy, &goproxy.Auth{
		User:     socksUser,
		Password: socksPass,
	}, goproxy.Direct)
	if err != nil {
		logrus.Fatalf("socks5 error: %v", err)
	}
	return proxyDialer.Dial("tcp", serverAddr)
}

// connect is used when connecting using direct connection.
func connect(conn net.Conn) error {
	yamuxConn, err := yamux.Server(conn, yamux.DefaultConfig())
	if err != nil {
		return err
	}

	logrus.WithFields(logrus.Fields{"addr": conn.RemoteAddr()}).Info("Connection established")

	for {
		conn, err := yamuxConn.Accept()
		if err != nil {
			return err
		}
		go agent.HandleConn(conn)
	}
}

func bind(config *tls.Config, bindAddr string) {
	selfcrt := tlsutils.NewSelfCert(nil)
	crt, err := selfcrt.GetCertificate(bindAddr)
	if err != nil {
		logrus.Fatal(err)
	}
	logrus.Warnf("TLS Certificate fingerprint is: %X\n", sha256.Sum256(crt.Certificate[0]))
	config.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return crt, nil
	}
	lis, err := net.Listen("tcp", bindAddr)
	if err != nil {
		logrus.Fatal(err)
	}
	logrus.Infof("Listening on %s...", bindAddr)
	for {
		conn, err := lis.Accept()
		if err != nil {
			logrus.Error(err)
			continue
		}
		logrus.Infof("Got connection from: %s\n", conn.RemoteAddr())
		tlsConn := tls.Server(conn, config)

		if err := connect(tlsConn); err != nil {
			logrus.Error(err)
		}
	}
}

// wsconnect is used to connect using websockets.
func wsconnect(config *tls.Config, wsaddr string, proxy string, useragent string) error {

	//timeout for websocket library connection - 20 seconds
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
	defer cancel()

	//in case of websocket proxy can be http with login:pass
	//Ex: proxystr = "http://admin:secret@127.0.0.1:8080"
	var proxyUrl *url.URL
	if proxy != "" {
		var err error
		proxyUrl, err = url.Parse(proxy)
		if err != nil {
			return fmt.Errorf("wsconnect: proxy url is invalid: %v", err)
		}
	}

	wsUrl, err := utils.ParseLigoloURL(wsaddr)
	if err != nil {
		return fmt.Errorf("wsconnect: wsaddr is invalid: %v", err)
	}

	httpTransport := &http.Transport{
		MaxIdleConns: http.DefaultMaxIdleConnsPerHost,
		Proxy:        http.ProxyURL(proxyUrl),
	}

	if wsUrl.IsSecure() {
		config.MinVersion = tls.VersionTLS11
		httpTransport.TLSClientConfig = config
	}

	httpClient := &http.Client{Transport: httpTransport}
	httpheader := &http.Header{}
	httpheader.Add("User-Agent", useragent)

	wsConn, _, err := websocket.Dial(ctx, wsaddr, &websocket.DialOptions{HTTPClient: httpClient, HTTPHeader: *httpheader})
	if err != nil {
		return err
	}

	netctx, cancel := context.WithCancel(context.Background())
	netConn := websocket.NetConn(netctx, wsConn, websocket.MessageBinary)
	defer cancel()

	yamuxConn, err := yamux.Server(netConn, yamux.DefaultConfig())
	if err != nil {
		return err
	}

	logrus.Info("Websocket connection established")
	for {
		conn, err := yamuxConn.Accept()
		if err != nil {
			return err
		}
		go agent.HandleConn(conn)
	}
}

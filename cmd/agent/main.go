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
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/allsmog/ligolo-ng-relay/pkg/tlsutils"
	"github.com/allsmog/ligolo-ng-relay/pkg/utils"

	"github.com/allsmog/ligolo-ng-relay/pkg/agent"
	"github.com/allsmog/ligolo-ng-relay/pkg/protocol"
	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
	"github.com/sirupsen/logrus"
	goproxy "golang.org/x/net/proxy"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

type connectionTarget struct {
	connectAddr       string
	acceptFingerprint string
	relayToken        string
}

func main() {
	var ignoreCertificate = flag.Bool("ignore-cert", false, "ignore TLS certificate validation (dangerous), only for debug purposes")
	var acceptFingerprint = flag.String("accept-fingerprint", "", "accept certificates matching the following SHA256 fingerprint (hex format)")
	var verbose = flag.Bool("v", false, "enable verbose mode")
	var retry = flag.Bool("retry", false, "auto-retry on initial connection error")
	var retryDelay = flag.Int("retry-delay", 5, "retry delay in seconds for initial connection (default: 5)")
	var reconnect = flag.Bool("reconnect", true, "auto-reconnect after established connection is lost")
	var reconnectDelay = flag.Int("reconnect-delay", 20, "reconnection delay in seconds (default: 20)")
	var reconnectTimeout = flag.Int("reconnect-timeout", 300, "total reconnection timeout in seconds (default: 300 = 5 minutes)")
	var socksProxy = flag.String("proxy", "", "proxy URL address (http://admin:secret@127.0.0.1:8080) or socks://admin:secret@127.0.0.1:8080")
	var serverAddr = flag.String("connect", "", "connect to proxy (domain:port)")
	var relayToken = flag.String("relay-token", os.Getenv("LIGOLO_RELAY_TOKEN"), "relay authentication token (or LIGOLO_RELAY_TOKEN)")
	var bindAddr = flag.String("bind", "", "bind to ip:port")
	var userAgent = flag.String("ua", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36", "HTTP User-Agent")
	var versionFlag = flag.Bool("version", false, "show the current version")

	flag.Usage = func() {
		fmt.Printf("Ligolo-ng Relay %s / %s / %s\n", version, commit, date)
		fmt.Println("Maintained fork of upstream Ligolo-ng by @Nicocha30")
		fmt.Println("https://github.com/allsmog/ligolo-ng-relay")
		fmt.Printf("\nUsage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	if *versionFlag {
		fmt.Printf("Ligolo-ng Relay %s / %s / %s\n", version, commit, date)
		return
	}

	logrus.SetReportCaller(*verbose)

	if *verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}

	if *bindAddr != "" {
		var tlsConfig tls.Config
		bind(&tlsConfig, *bindAddr)
	}

	if *serverAddr == "" {
		logrus.Fatal("please, specify the target host user -connect host:port")
	}

	if _, err := utils.ParseLigoloURL(*serverAddr); err != nil {
		logrus.Fatalf("Invalid connect address, please use http(s)://host:port for websocket or host:port for tcp")
	}

	if *ignoreCertificate {
		logrus.Warn("warning, certificate validation disabled")
	}

	// Validate retry and reconnect delays
	if *retryDelay < 1 {
		logrus.Fatal("retry-delay must be at least 1 second")
	}
	if *reconnectDelay < 1 {
		logrus.Fatal("reconnect-delay must be at least 1 second")
	}
	if *reconnectTimeout < *reconnectDelay {
		logrus.Fatal("reconnect-timeout must be greater than reconnect-delay")
	}

	var conn net.Conn
	connectionEstablished := false
	var reconnectStartTime time.Time
	var reconnectAttempt int
	targetMu := sync.RWMutex{}
	target := connectionTarget{
		connectAddr:       *serverAddr,
		acceptFingerprint: *acceptFingerprint,
		relayToken:        *relayToken,
	}

	agent.SetReconnectRequestHandler(func(request protocol.AgentReconnectRequestPacket) error {
		if request.ConnectAddr == "" {
			return fmt.Errorf("reconnect target is empty")
		}
		if _, err := utils.ParseLigoloURL(request.ConnectAddr); err != nil {
			return fmt.Errorf("invalid reconnect target: %v", err)
		}
		targetMu.Lock()
		target = connectionTarget{
			connectAddr:       request.ConnectAddr,
			acceptFingerprint: request.AcceptFingerprint,
			relayToken:        request.RelayToken,
		}
		targetMu.Unlock()
		logrus.WithField("connect", request.ConnectAddr).Info("Reconnect target updated by proxy")
		return nil
	})

	for {
		var err error
		var connSuccess bool
		targetMu.RLock()
		currentTarget := target
		targetMu.RUnlock()

		ligoloUrl, err := utils.ParseLigoloURL(currentTarget.connectAddr)
		if err != nil {
			logrus.Fatalf("Invalid connect address, please use http(s)://host:port for websocket or host:port for tcp")
		}
		tlsConfig := tls.Config{
			ServerName: ligoloUrl.Hostname(),
		}
		if *ignoreCertificate {
			tlsConfig.InsecureSkipVerify = true
		}

		if ligoloUrl.IsWebsocket() {
			//websocket
			connSuccess, err = wsconnect(&tlsConfig, currentTarget.connectAddr, *socksProxy, *userAgent)
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
					conn, err = sockDial(currentTarget.connectAddr, proxyUrl.Host, proxyUrl.User.Username(), pass)
				} else {
					logrus.Fatal("invalid socks5 address, please use socks://host:port")
				}
			} else {
				conn, err = net.Dial("tcp", currentTarget.connectAddr)
			}
			if err == nil {
				if currentTarget.acceptFingerprint != "" {
					crtMatch, decodeErr := hex.DecodeString(currentTarget.acceptFingerprint)
					if decodeErr != nil {
						conn.Close()
						err = fmt.Errorf("invalid cert fingerprint: %v", decodeErr)
					} else {
						tlsConfig.InsecureSkipVerify = true
						tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
							if len(state.PeerCertificates) == 0 {
								return fmt.Errorf("server did not present a certificate")
							}
							crtFingerprint := sha256.Sum256(state.PeerCertificates[0].Raw)
							if subtle.ConstantTimeCompare(crtMatch, crtFingerprint[:]) != 1 {
								return fmt.Errorf("certificate does not match fingerprint: %X != %X", crtFingerprint, crtMatch)
							}
							return nil
						}
					}
				}
				if err == nil {
					tlsConn := tls.Client(conn, &tlsConfig)
					if currentTarget.relayToken != "" {
						if authErr := agent.WriteRelayAuth(tlsConn, currentTarget.relayToken); authErr != nil {
							conn.Close()
							err = fmt.Errorf("relay auth failed: %v", authErr)
						} else {
							connSuccess, err = connect(tlsConn)
						}
					} else {
						connSuccess, err = connect(tlsConn)
					}
				}
			}
		}

		// If connection was successful at any point, mark it as established
		if connSuccess {
			connectionEstablished = true
			// Reset reconnection tracking when successfully connected
			reconnectStartTime = time.Time{}
			reconnectAttempt = 0
		}

		// If we reach here, there was an error
		if err != nil {
			logrus.Errorf("Connection error: %v", err)
		}

		// Determine retry/reconnect behavior
		if !connectionEstablished {
			// Initial connection attempt failed
			if *retry {
				logrus.Infof("Retrying initial connection in %d seconds.", *retryDelay)
				time.Sleep(time.Duration(*retryDelay) * time.Second)
				continue
			} else {
				logrus.Fatal("Initial connection failed. Use -retry flag to enable automatic retry.")
			}
		} else {
			// Connection was previously established but now lost
			if *reconnect {
				// Initialize reconnection tracking on first reconnect attempt
				if reconnectStartTime.IsZero() {
					logrus.Warn("Connection lost. Attempting to reconnect...")
					reconnectStartTime = time.Now()
					reconnectAttempt = 0
				}

				reconnectAttempt++
				elapsed := time.Since(reconnectStartTime)

				if elapsed.Seconds() >= float64(*reconnectTimeout) {
					logrus.Fatalf("Reconnection timeout reached after %d attempts over %.0f seconds. Giving up.", reconnectAttempt, elapsed.Seconds())
				}

				logrus.Infof("Reconnection attempt %d (elapsed: %.0fs/%.0fs). Waiting %d seconds...", reconnectAttempt, elapsed.Seconds(), float64(*reconnectTimeout), *reconnectDelay)
				time.Sleep(time.Duration(*reconnectDelay) * time.Second)
			} else {
				logrus.Fatal("Connection lost and reconnect is disabled.")
			}
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
func connect(conn net.Conn) (bool, error) {
	// Configure yamux with longer timeouts for multi-hop scenarios
	yamuxConfig := yamux.DefaultConfig()
	yamuxConfig.EnableKeepAlive = true
	yamuxConfig.KeepAliveInterval = 60 * time.Second       // Increased from 30s
	yamuxConfig.ConnectionWriteTimeout = 120 * time.Second // Increased from 60s
	yamuxConfig.MaxStreamWindowSize = 16 * 1024 * 1024     // 16MB window

	yamuxConn, err := yamux.Server(conn, yamuxConfig)
	if err != nil {
		return false, err
	}

	logrus.WithFields(logrus.Fields{"addr": conn.RemoteAddr()}).Info("Connection established")

	for {
		conn, err := yamuxConn.Accept()
		if err != nil {
			agent.CloseListeners()
			return true, err // Connection was established but now lost
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

		if connSuccess, err := connect(tlsConn); err != nil {
			logrus.Error(err)
		} else if connSuccess {
			// This shouldn't happen as connect only returns on error, but for safety
			logrus.Info("Connection closed normally")
		}
	}
}

// wsconnect is used to connect using websockets.
func wsconnect(config *tls.Config, wsaddr string, proxy string, useragent string) (bool, error) {
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
			return false, fmt.Errorf("wsconnect: proxy url is invalid: %v", err)
		}
	}

	wsUrl, err := utils.ParseLigoloURL(wsaddr)
	if err != nil {
		return false, fmt.Errorf("wsconnect: wsaddr is invalid: %v", err)
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
		return false, err
	}

	netctx, cancel := context.WithCancel(context.Background())
	netConn := websocket.NetConn(netctx, wsConn, websocket.MessageBinary)
	defer cancel()

	// FIXED: Configure yamux with better timeout settings for websocket double-hop too
	yamuxConfig := yamux.DefaultConfig()
	yamuxConfig.EnableKeepAlive = true
	yamuxConfig.KeepAliveInterval = 60 * time.Second       // Increased
	yamuxConfig.ConnectionWriteTimeout = 120 * time.Second // Increased
	yamuxConfig.MaxStreamWindowSize = 16 * 1024 * 1024     // 16MB window

	yamuxConn, err := yamux.Server(netConn, yamuxConfig)
	if err != nil {
		return false, err
	}

	logrus.Info("Websocket connection established")
	for {
		conn, err := yamuxConn.Accept()
		if err != nil {
			return true, err // Connection was established but now lost
		}
		go agent.HandleConn(conn)
	}
}

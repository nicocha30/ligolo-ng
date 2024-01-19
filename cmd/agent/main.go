package main

import (
	"context"
	"crypto/tls"
	"flag"
	"github.com/hashicorp/yamux"
	"github.com/nicocha30/ligolo-ng/pkg/agent"
	"github.com/sirupsen/logrus"
	goproxy "golang.org/x/net/proxy"
	"net"
	"net/http"
	"net/url"
	"nhooyr.io/websocket"
	"strings"
	"time"
)

func main() {
	var tlsConfig tls.Config
	var ignoreCertificate = flag.Bool("ignore-cert", false, "ignore TLS certificate validation (dangerous), only for debug purposes")
	var verbose = flag.Bool("v", false, "enable verbose mode")
	var retry = flag.Int("retry", 0, "auto-retry on error with delay in sec. If 0 then no auto-retry")
	var socksProxy = flag.String("proxy", "", "proxy URL address (http://admin:secret@127.0.0.1:8080)"+
		" or socks://admin:secret@127.0.0.1:8080")
	var serverAddr = flag.String("connect", "", "the target (domain:port)")
	var userAgent = flag.String("ua", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "+
		"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36", "http User-Agent")

	flag.Parse()

	logrus.SetReportCaller(*verbose)

	if *verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}

	if *serverAddr == "" {
		logrus.Fatal("please, specify the target host user -connect host:port")
	}

	if strings.Contains(*serverAddr, "https://") {
		//websocket https connection
		host, _, err := net.SplitHostPort(strings.Replace(*serverAddr, "https://", "", 1))
		if err != nil {
			logrus.Info("There is no port in address string, assuming that port is 443")
			host = strings.Replace(*serverAddr, "https://", "", 1)
		}
		tlsConfig.ServerName = host
	} else if strings.Contains(*serverAddr, "http://") {
		//websocket http connection
		host, _, err := net.SplitHostPort(strings.Replace(*serverAddr, "http://", "", 1))
		if err != nil {
			logrus.Info("There is no port in address string, assuming that port is 80")
			host = strings.Replace(*serverAddr, "http://", "", 1)
		}
		tlsConfig.ServerName = host
	} else {
		//direct connection
		host, _, err := net.SplitHostPort(*serverAddr)
		if err != nil {
			logrus.Fatal("Invalid connect address, please use host:port")
		}
		tlsConfig.ServerName = host
	}

	if *ignoreCertificate {
		logrus.Warn("Warning, certificate validation disabled")
		tlsConfig.InsecureSkipVerify = true
	}

	var conn net.Conn

	for {
		var err error
		if strings.Contains(*serverAddr, "http://") || strings.Contains(*serverAddr, "https://") ||
			strings.Contains(*serverAddr, "wss://") || strings.Contains(*serverAddr, "ws://") {
			*serverAddr = strings.Replace(*serverAddr, "https://", "wss://", 1)
			*serverAddr = strings.Replace(*serverAddr, "http://", "ws://", 1)
			//websocket
			err = wsconnect(&tlsConfig, *serverAddr, *socksProxy, *userAgent)
		} else {
			if *socksProxy != "" {
				if strings.Contains(*socksProxy, "http://") {
					//TODO http proxy CONNECT
				} else {
					//suppose that scheme is socks:// or socks5://
					var proxyUrl *url.URL
					proxyUrl, err = url.Parse(*socksProxy)
					if err != nil {
						logrus.Fatal("invalid socks5 address, please use host:port")
					}
					if _, _, err = net.SplitHostPort(proxyUrl.Host); err != nil {
						logrus.Fatal("invalid socks5 address, please use socks://host:port")
					}
					pass, _ := proxyUrl.User.Password()
					conn, err = sockDial(*serverAddr, proxyUrl.Host, proxyUrl.User.Username(), pass)
					if err != nil {
						logrus.Errorf("Socks connection error: %v", err)
					} else {
						logrus.Infof("Connection to socks success.")
					}
				}
			} else {
				//direct connection
				conn, err = net.Dial("tcp", *serverAddr)
			}
			if err == nil {
				err = connect(conn, &tlsConfig)
			}
		}

		logrus.Errorf("Connection error: %v", err)
		if *retry > 0 {
			logrus.Infof("Retrying in %d seconds.", *retry)
			time.Sleep(time.Duration(*retry) * time.Second)
		} else {
			logrus.Fatal(err)
		}
	}
}

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

func connect(conn net.Conn, config *tls.Config) error {
	tlsConn := tls.Client(conn, config)

	yamuxConn, err := yamux.Server(tlsConn, yamux.DefaultConfig())
	if err != nil {
		return err
	}
	logrus.WithFields(logrus.Fields{"addr": tlsConn.RemoteAddr()}).Info("Connection established")
	for {
		conn, err := yamuxConn.Accept()
		if err != nil {
			return err
		}
		go agent.HandleConn(conn)
	}
}

func wsconnect(config *tls.Config, wsaddr string, proxystr string, useragent string) error {
	var nossl bool

	if strings.Contains(wsaddr, "ws://") {
		nossl = true
	} else {
		nossl = false
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
	defer cancel()

	//proxystr = "http://admin:secret@127.0.0.1:8080"
	proxyUrl, err := url.Parse(proxystr)
	if err != nil || proxystr == "" {
		proxyUrl = nil
	}

	httpTransport := &http.Transport{}
	config.MinVersion = tls.VersionTLS10

	if nossl {
		httpTransport = &http.Transport{
			MaxIdleConns: http.DefaultMaxIdleConnsPerHost,
			Proxy:        http.ProxyURL(proxyUrl),
		}
	} else {
		httpTransport = &http.Transport{
			MaxIdleConns:    http.DefaultMaxIdleConnsPerHost,
			TLSClientConfig: config,
			Proxy:           http.ProxyURL(proxyUrl),
		}
	}

	httpClient := &http.Client{Transport: httpTransport}
	httpheader := &http.Header{}
	httpheader.Add("User-Agent", useragent)

	wsConn, _, err := websocket.Dial(ctx, wsaddr, &websocket.DialOptions{HTTPClient: httpClient, HTTPHeader: *httpheader})
	if err != nil {
		return err
	}

	netctx, cancel := context.WithTimeout(context.Background(), time.Hour*999999)
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
	//return nil
}

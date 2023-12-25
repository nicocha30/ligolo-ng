package main

import (
	"crypto/tls"
	"flag"
	"github.com/hashicorp/yamux"
	"github.com/nicocha30/ligolo-ng/pkg/agent"
	"github.com/sirupsen/logrus"
	goproxy "golang.org/x/net/proxy"
	"net"
	"time"
)

func main() {
	var tlsConfig tls.Config
	var ignoreCertificate = flag.Bool("ignore-cert", false, "ignore TLS certificate validation (dangerous), only for debug purposes")
	var verbose = flag.Bool("v", false, "enable verbose mode")
	var retry = flag.Bool("retry", false, "auto-retry on error")
	var socksProxy = flag.String("socks", "", "socks5 proxy address (ip:port)")
	var socksUser = flag.String("socks-user", "", "socks5 username")
	var socksPass = flag.String("socks-pass", "", "socks5 password")
	var serverAddr = flag.String("connect", "", "the target (domain:port)")

	flag.Parse()

	logrus.SetReportCaller(*verbose)

	if *verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}

	if *serverAddr == "" {
		logrus.Fatal("please, specify the target host user -connect host:port")
	}
	host, _, err := net.SplitHostPort(*serverAddr)
	if err != nil {
		logrus.Fatal("invalid connect address, please use host:port")
	}
	tlsConfig.ServerName = host
	if *ignoreCertificate {
		logrus.Warn("warning, certificate validation disabled")
		tlsConfig.InsecureSkipVerify = true
	}

	var conn net.Conn

	for {
		var err error
		if *socksProxy != "" {
			if _, _, err := net.SplitHostPort(*socksProxy); err != nil {
				logrus.Fatal("invalid socks5 address, please use host:port")
			}
			conn, err = sockDial(*serverAddr, *socksProxy, *socksUser, *socksPass)
		} else {
			conn, err = net.Dial("tcp", *serverAddr)
		}
		if err == nil {
			err = connect(conn, &tlsConfig)
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

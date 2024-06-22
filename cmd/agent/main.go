package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/hashicorp/yamux"
	"github.com/nicocha30/ligolo-ng/pkg/agent"
	"github.com/nicocha30/ligolo-ng/pkg/utils/selfcert"
	"github.com/sirupsen/logrus"
	goproxy "golang.org/x/net/proxy"
	"net"
	"os"
	"time"
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
	var socksProxy = flag.String("socks", "", "socks5 proxy address (ip:port)")
	var socksUser = flag.String("socks-user", "", "socks5 username")
	var socksPass = flag.String("socks-pass", "", "socks5 password")
	var serverAddr = flag.String("connect", "", "connect to proxy (domain:port)")
	var bindAddr = flag.String("bind", "", "bind to ip:port")

	flag.Usage = func() {
		fmt.Printf("Ligolo-ng %s / %s / %s\n", version, commit, date)
		fmt.Println("Made in France with love by @Nicocha30!")
		fmt.Println("https://github.com/nicocha30/ligolo-ng\n")
		fmt.Printf("Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	logrus.SetReportCaller(*verbose)

	if *verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}

	if *bindAddr != "" {
		selfcrt := selfcert.NewSelfCert(nil)
		crt, err := selfcrt.GetCertificate(*bindAddr)
		if err != nil {
			logrus.Fatal(err)
		}
		logrus.Warnf("TLS Certificate fingerprint is: %X\n", sha256.Sum256(crt.Certificate[0]))
		tlsConfig.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return crt, nil
		}
		lis, err := net.Listen("tcp", *bindAddr)
		if err != nil {
			logrus.Fatal(err)
		}
		logrus.Infof("Listening on %s...", *bindAddr)
		for {
			conn, err := lis.Accept()
			if err != nil {
				logrus.Error(err)
				continue
			}
			logrus.Infof("Got connection from: %s\n", conn.RemoteAddr())
			tlsConn := tls.Server(conn, &tlsConfig)

			if err := connect(tlsConn); err != nil {
				logrus.Error(err)
			}
		}
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

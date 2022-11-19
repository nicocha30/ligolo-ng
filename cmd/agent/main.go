package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"github.com/hashicorp/yamux"
	"github.com/nicocha30/ligolo-ng/pkg/agent/neterror"
	"github.com/nicocha30/ligolo-ng/pkg/agent/smartping"
	"github.com/nicocha30/ligolo-ng/pkg/protocol"
	"github.com/nicocha30/ligolo-ng/pkg/relay"
	"github.com/sirupsen/logrus"
	goproxy "golang.org/x/net/proxy"
	"net/http"
	"regexp"
	"strings"

	"net"

	"github.com/likexian/doh-go"
	"github.com/likexian/doh-go/dns"
	"nhooyr.io/websocket"
	"os"
	"os/user"
	"syscall"
	"time"
)

var listenerConntrack map[int32]net.Conn
var listenerMap map[int32]net.Listener
var connTrackID int32
var listenerID int32

func main() {
	var tlsConfig tls.Config
	var ignoreCertificate = flag.Bool("ignore-cert", false, "ignore TLS certificate validation (dangerous), only for debug purposes")
	var verbose = flag.Bool("v", false, "enable verbose mode")
	var ech = flag.Bool("ech", false, "enable TLS1.3 Enrypted Client Hello (TLS domain fronting)")
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

	if strings.Contains(*serverAddr, "https://") {
		//websocket connection
		host, _, err := net.SplitHostPort(strings.Replace(*serverAddr, "https://", "", 1))
		if err != nil {
			logrus.Fatal("invalid https address, please use https://host:port")
		}
		tlsConfig.ServerName = host
		if *ignoreCertificate {
			logrus.Warn("warning, certificate validation disabled")
			tlsConfig.InsecureSkipVerify = true
		}
	} else {
		//direct connection
		host, _, err := net.SplitHostPort(*serverAddr)
		if err != nil {
			logrus.Fatal("invalid connect address, please use host:port")
		}
		tlsConfig.ServerName = host
		if *ignoreCertificate {
			logrus.Warn("warning, certificate validation disabled")
			tlsConfig.InsecureSkipVerify = true
		}
	}

	var conn net.Conn

	listenerConntrack = make(map[int32]net.Conn)
	listenerMap = make(map[int32]net.Listener)

	for {
		var err error
		if strings.Contains(*serverAddr, "https://") {
			*serverAddr = strings.Replace(*serverAddr, "https://", "wss://", 1)
			//websocket
			err = wsconnect(&tlsConfig, *serverAddr, *ech)
		} else {
			//direct connection
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

func DoHGetECHKeys(servername string) []tls.ECHConfig {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c := doh.Use(doh.GoogleProvider)

	// do doh query
	rsp, err := c.Query(ctx, dns.Domain(servername), dns.Type("TYPE65"))
	if err != nil {
		return nil
	}
	c.Close()

	//regex for Google DoH provider
	//if we use CloudFlare DoH provider regex will be other !!
	r, _ := regexp.Compile("ech=.*? ")
	ech := r.FindString(rsp.Answer[0].Data)

	echbin, err := base64.StdEncoding.DecodeString(strings.TrimSpace(ech[4:]))
	if err != nil {
		return nil
	}
	echConfigsList, err := tls.UnmarshalECHConfigs(echbin)
	if err != nil {
		return nil
	}
	return echConfigsList
}

func wsconnect(config *tls.Config, wsaddr string, useECH bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
	defer cancel()

	if useECH {
		echConfigsList := DoHGetECHKeys("crypto.cloudflare.com")
		if echConfigsList != nil {
			logrus.Info("Got ECH keys. Using TLS1.3 ECH...")
			config.ECHEnabled = true
			config.ClientECHConfigs = echConfigsList
			config.MinVersion = tls.VersionTLS12
		} else {
			logrus.Info("Error with ECH keys. Using plaintext SNI :( ...")
			config.ECHEnabled = false
			config.MinVersion = tls.VersionTLS11
		}
	}

	httpTransport := &http.Transport{
		MaxIdleConns:    http.DefaultMaxIdleConnsPerHost,
		TLSClientConfig: config,
	}
	httpClient := &http.Client{Transport: httpTransport}

	httpheader := &http.Header{}
	httpheader.Add("X-Agent", "Ligolo-NG")

	wsConn, _, err := websocket.Dial(ctx, wsaddr, &websocket.DialOptions{HTTPClient: httpClient, HTTPHeader: *httpheader})
	if err != nil {
		return err
	}

	netctx, _ := context.WithTimeout(context.Background(), time.Hour*999999)
	netConn := websocket.NetConn(netctx, wsConn, websocket.MessageBinary)
	yamuxConn, err := yamux.Server(netConn, yamux.DefaultConfig())
	if err != nil {
		return err
	}

	logrus.WithFields(logrus.Fields{"addr": netConn.RemoteAddr()}).Info("websocket connection established")

	for {

		conn, err := yamuxConn.Accept()
		if err != nil {
			return err
		}
		go handleConn(conn)
	}

	return nil
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
		go handleConn(conn)
	}
}

// Listener is the base class implementing listener sockets for Ligolo
type Listener struct {
	net.Listener
}

// NewListener register a new listener
func NewListener(network string, addr string) (Listener, error) {
	lis, err := net.Listen(network, addr)
	if err != nil {
		return Listener{}, err
	}
	return Listener{lis}, nil
}

// ListenAndServe fill new listener connections to a channel
func (s *Listener) ListenAndServe(connTrackChan chan int32) error {
	for {
		conn, err := s.Accept()
		if err != nil {
			return err
		}
		connTrackID++
		connTrackChan <- connTrackID
		listenerConntrack[connTrackID] = conn
	}
}

// Close request the main listener to exit
func (s *Listener) Close() error {
	return s.Listener.Close()
}

func handleConn(conn net.Conn) {
	decoder := protocol.NewDecoder(conn)
	if err := decoder.Decode(); err != nil {
		panic(err)
	}

	e := decoder.Envelope.Payload
	switch decoder.Envelope.Type {

	case protocol.MessageConnectRequest:
		connRequest := e.(protocol.ConnectRequestPacket)
		encoder := protocol.NewEncoder(conn)

		logrus.Debugf("Got connect request to %s:%d", connRequest.Address, connRequest.Port)
		var network string
		if connRequest.Transport == protocol.TransportTCP {
			network = "tcp"
		} else {
			network = "udp"
		}
		if connRequest.Net == protocol.Networkv4 {
			network += "4"
		} else {
			network += "6"
		}

		var d net.Dialer
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		targetConn, err := d.DialContext(ctx, network, fmt.Sprintf("%s:%d", connRequest.Address, connRequest.Port))
		defer cancel()

		var connectPacket protocol.ConnectResponsePacket
		if err != nil {

			var serr syscall.Errno
			if errors.As(err, &serr) {
				// Magic trick ! If the error syscall indicate that the system responded, send back a RST packet!
				if neterror.HostResponded(serr) {
					connectPacket.Reset = true
				}
			}

			connectPacket.Established = false
		} else {
			connectPacket.Established = true
		}
		if err := encoder.Encode(protocol.Envelope{
			Type:    protocol.MessageConnectResponse,
			Payload: connectPacket,
		}); err != nil {
			logrus.Fatal(err)
		}
		if connectPacket.Established {
			relay.StartRelay(targetConn, conn)
		}
	case protocol.MessageHostPingRequest:
		pingRequest := e.(protocol.HostPingRequestPacket)
		encoder := protocol.NewEncoder(conn)

		pingResponse := protocol.HostPingResponsePacket{Alive: smartping.TryResolve(pingRequest.Address)}

		if err := encoder.Encode(protocol.Envelope{
			Type:    protocol.MessageHostPingResponse,
			Payload: pingResponse,
		}); err != nil {
			logrus.Fatal(err)
		}
	case protocol.MessageInfoRequest:
		var username string
		encoder := protocol.NewEncoder(conn)
		hostname, err := os.Hostname()
		if err != nil {
			hostname = "UNKNOWN"
		}

		userinfo, _ := user.Current()
		if err != nil {
			username = "Unknown"
		} else {
			username = userinfo.Username
		}

		netifaces, err := net.Interfaces()
		if err != nil {
			logrus.Error("could not get network interfaces")
			return
		}
		infoResponse := protocol.InfoReplyPacket{
			Name:       fmt.Sprintf("%s@%s", username, hostname),
			Interfaces: protocol.NewNetInterfaces(netifaces),
		}

		if err := encoder.Encode(protocol.Envelope{
			Type:    protocol.MessageInfoReply,
			Payload: infoResponse,
		}); err != nil {
			logrus.Fatal(err)
		}
	case protocol.MessageListenerCloseRequest:
		// Request to close a listener
		closeRequest := e.(protocol.ListenerCloseRequestPacket)
		encoder := protocol.NewEncoder(conn)

		var err error
		if lis, ok := listenerMap[closeRequest.ListenerID]; ok {
			err = lis.Close()
		} else {
			err = errors.New("invalid listener id")
		}

		listenerResponse := protocol.ListenerCloseResponsePacket{
			Err: err != nil,
		}
		if err != nil {
			listenerResponse.ErrString = err.Error()
		}

		if err := encoder.Encode(protocol.Envelope{
			Type:    protocol.MessageListenerCloseResponse,
			Payload: listenerResponse,
		}); err != nil {
			logrus.Error(err)
		}

	case protocol.MessageListenerRequest:
		listenRequest := e.(protocol.ListenerRequestPacket)
		encoder := protocol.NewEncoder(conn)
		connTrackChan := make(chan int32)
		stopChan := make(chan error)

		listener, err := NewListener(listenRequest.Network, listenRequest.Address)
		if err != nil {
			listenerResponse := protocol.ListenerResponsePacket{
				ListenerID: 0,
				Err:        true,
				ErrString:  err.Error(),
			}
			if err := encoder.Encode(protocol.Envelope{
				Type:    protocol.MessageListenerResponse,
				Payload: listenerResponse,
			}); err != nil {
				logrus.Error(err)
			}
			return
		}

		listenerResponse := protocol.ListenerResponsePacket{
			ListenerID: listenerID,
			Err:        false,
			ErrString:  "",
		}
		listenerMap[listenerID] = listener.Listener
		listenerID++

		if err := encoder.Encode(protocol.Envelope{
			Type:    protocol.MessageListenerResponse,
			Payload: listenerResponse,
		}); err != nil {
			logrus.Error(err)
		}

		go func() {
			if err := listener.ListenAndServe(connTrackChan); err != nil {
				stopChan <- err
			}
		}()
		defer listener.Close()

		for {
			var bindResponse protocol.ListenerBindReponse
			select {
			case err := <-stopChan:
				logrus.Error(err)
				bindResponse = protocol.ListenerBindReponse{
					SockID:    0,
					Err:       true,
					ErrString: err.Error(),
				}
			case connTrackID := <-connTrackChan:
				bindResponse = protocol.ListenerBindReponse{
					SockID: connTrackID,
					Err:    false,
				}
			}

			if err := encoder.Encode(protocol.Envelope{
				Type:    protocol.MessageListenerBindResponse,
				Payload: bindResponse,
			}); err != nil {
				logrus.Error(err)
			}

			if bindResponse.Err {
				break
			}

		}
	case protocol.MessageListenerSockRequest:
		sockRequest := e.(protocol.ListenerSockRequestPacket)
		encoder := protocol.NewEncoder(conn)

		var sockResponse protocol.ListenerSockResponsePacket
		if _, ok := listenerConntrack[sockRequest.SockID]; !ok {
			// Handle error
			sockResponse.ErrString = "invalid or unexistant SockID"
			sockResponse.Err = true
		}

		if err := encoder.Encode(protocol.Envelope{
			Type:    protocol.MessageListenerSockResponse,
			Payload: sockResponse,
		}); err != nil {
			logrus.Fatal(err)
		}

		if sockResponse.Err {
			return
		}

		netConn := listenerConntrack[sockRequest.SockID]
		relay.StartRelay(netConn, conn)

	case protocol.MessageClose:
		os.Exit(0)

	}
}

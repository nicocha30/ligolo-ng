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

package app

import (
	"fmt"
	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/static"
	"github.com/gin-gonic/gin"
	"github.com/nicocha30/ligolo-ng/cmd/proxy/config"
	"github.com/nicocha30/ligolo-ng/pkg/proxy/netinfo"
	"github.com/nicocha30/ligolo-ng/pkg/tlsutils"
	"github.com/nicocha30/ligolo-ng/web"
	"github.com/sirupsen/logrus"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)
import "github.com/golang-jwt/jwt/v5"

var (
	internalServerError = gin.H{"error": "internal server error"}
	inputError          = gin.H{"error": "input error"}
)

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")

		// Parse the token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, http.ErrAbortHandler
			}
			return []byte(config.Config.GetString("web.secret")), nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort() // Stop further processing if unauthorized
			return
		}

		// Set the token claims to the context
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			c.Set("claims", claims)
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		c.Next() // Proceed to the next handler if authorized
	}
}

func GetAPIUrl() string {
	targetDomain := config.Config.GetString("web.listen")
	scheme := "http"
	if config.Config.GetBool("web.tls.enabled") {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s", scheme, targetDomain)
}

func StartLigoloApi() {
	if config.Config.GetBool("web.debug") {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}
	logrus.Warn("Ligolo-ng API is experimental, and should be running behind a reverse-proxy if publicly exposed.")

	if config.Config.GetString("web.logfile") != "" {
		f, err := os.Create(config.Config.GetString("web.logfile"))
		if err != nil {
			logrus.Fatal(err)
		}
		gin.DisableConsoleColor()
		gin.DefaultWriter = io.MultiWriter(f)
	}

	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     config.Config.GetStringSlice("web.corsallowedorigin"),
		AllowMethods:     []string{"PUT", "PATCH", "GET", "POST", "DELETE"},
		AllowHeaders:     []string{"Origin", "Authorization", "Content-Type"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))
	if err := r.SetTrustedProxies(config.Config.GetStringSlice("web.trustedproxies")); err != nil {
		logrus.Fatal(err)
	}
	r.ForwardedByClientIP = config.Config.GetBool("web.behindreverseproxy")

	if config.Config.GetBool("web.enableui") {
		eFs, err := static.EmbedFolder(web.LigoloWebFS, "dist")
		if err != nil {
			logrus.Fatal(err)
		}
		r.Use(static.Serve("/", eFs))
		r.NoRoute(func(c *gin.Context) {
			if !strings.HasPrefix(c.Request.RequestURI, "/api") {
				c.FileFromFS("index.html", eFs)
			}
		})
	}

	r.POST("/api/auth", func(c *gin.Context) {
		type AuthInfo struct {
			Username string
			Password string
		}
		var authInfo AuthInfo
		if err := c.ShouldBindJSON(&authInfo); err != nil {
			c.JSON(http.StatusInternalServerError, inputError)
			return
		}
		if !config.CheckAuth(authInfo.Username, authInfo.Password) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid credentials"})
			return
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"username": authInfo.Username,
			"exp":      time.Now().Add(time.Hour * 1).Unix(),
		})
		signedJwt, err := token.SignedString([]byte(config.Config.GetString("web.secret")))
		if err != nil {
			c.Error(err)
			c.JSON(http.StatusInternalServerError, internalServerError)
			return
		}
		c.JSON(http.StatusOK, gin.H{"token": signedJwt})
	})

	apiv1 := r.Group("/api/v1").Use(authMiddleware())
	{
		apiv1.GET("/ping", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"message": "pong",
			})
		})

		apiv1.GET("/interfaces", func(c *gin.Context) {
			interfaces, err := config.GetInterfaceConfigState()
			if err != nil {
				c.Error(err)
				c.JSON(http.StatusInternalServerError, internalServerError)
				return
			}

			c.IndentedJSON(http.StatusOK, interfaces)
		})

		apiv1.DELETE("/interfaces", func(c *gin.Context) {
			type InterfaceInfo struct {
				Interface string
			}
			var interfaceInfo InterfaceInfo
			if err := c.ShouldBindJSON(&interfaceInfo); err != nil {
				c.JSON(http.StatusInternalServerError, inputError)
				return
			}
			if err := config.DeleteInterfaceConfig(interfaceInfo.Interface); err != nil {
				c.Error(err)
			}
			if netinfo.InterfaceExist(interfaceInfo.Interface) {
				stun, err := netinfo.GetTunByName(interfaceInfo.Interface)
				if err != nil {
					c.Error(err)
					c.JSON(http.StatusInternalServerError, internalServerError)
					return
				}
				if err := stun.Destroy(); err != nil {
					c.Error(err)
					c.JSON(http.StatusInternalServerError, internalServerError)
					return
				}
			}
			c.JSON(http.StatusOK, gin.H{"message": "interface deleted"})
		})

		apiv1.POST("/interfaces", func(c *gin.Context) {
			type InterfaceInfo struct {
				Interface string
			}
			var interfaceInfo InterfaceInfo
			if err := c.ShouldBindJSON(&interfaceInfo); err != nil {
				c.JSON(http.StatusInternalServerError, inputError)
				return
			}
			if err := config.AddInterfaceConfig(interfaceInfo.Interface); err != nil {
				c.Error(err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			if netinfo.CanCreateTUNs() {
				if err := netinfo.CreateTUN(interfaceInfo.Interface); err != nil {
					c.Error(err)
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
				c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Interface %s created.", interfaceInfo.Interface)})
				return
			}
			c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Interface will %s be created on tunnel start.", interfaceInfo.Interface)})
		})

		apiv1.POST("/routes", func(c *gin.Context) {
			type RouteInfo struct {
				Interface string
				Route     []string
			}
			var routeInfo RouteInfo
			if err := c.ShouldBindJSON(&routeInfo); err != nil {
				c.JSON(http.StatusInternalServerError, inputError)
				return
			}
			for _, route := range routeInfo.Route {
				if err := config.AddRouteConfig(routeInfo.Interface, route); err != nil {
					c.Error(err)
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
			}

			if netinfo.InterfaceExist(routeInfo.Interface) {
				stun, err := netinfo.GetTunByName(routeInfo.Interface)
				if err != nil {
					c.Error(err)
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
				for _, route := range routeInfo.Route {
					if err := stun.AddRoute(route); err != nil {
						c.Error(err)
						c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
						return
					}
				}
				c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Routes %s added.", routeInfo.Route)})
				return
			}
			c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Routes %s will be created on tunnel start.", routeInfo.Route)})
			return
		})

		apiv1.DELETE("/routes", func(c *gin.Context) {
			type RouteInfo struct {
				Interface string
				Route     string
			}
			var routeInfo RouteInfo
			if err := c.ShouldBindJSON(&routeInfo); err != nil {
				c.JSON(http.StatusInternalServerError, inputError)
				return
			}
			if err := config.DeleteRouteConfig(routeInfo.Interface, routeInfo.Route); err != nil {
				c.Error(err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			if netinfo.InterfaceExist(routeInfo.Interface) {
				stun, err := netinfo.GetTunByName(routeInfo.Interface)
				if err != nil {
					c.Error(err)
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
				if err := stun.DelRoute(routeInfo.Route); err != nil {
					c.Error(err)
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
				c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Route %s deleted.", routeInfo.Route)})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Route %s does not exist.", routeInfo.Route)})
			return
		})

		apiv1.GET("/listeners", func(c *gin.Context) {
			type ListenerInfo struct {
				ListenerID   int32
				AgentID      int
				Agent        string
				RemoteAddr   string
				SessionID    string
				Network      string
				ListenerAddr string
				RedirectAddr string
				Online       bool
			}
			var listeners []ListenerInfo
			for agentId, agent := range AgentList {
				for _, listener := range agent.Listeners {
					listeners = append(listeners, ListenerInfo{
						ListenerID:   listener.ID,
						Agent:        agent.Name,
						AgentID:      agentId,
						RemoteAddr:   agent.Session.RemoteAddr().String(),
						SessionID:    agent.SessionID,
						Network:      listener.Network(),
						ListenerAddr: listener.ListenerAddr(),
						RedirectAddr: listener.RedirectAddr(),
						Online:       agent.Alive(),
					})
				}
			}
			c.IndentedJSON(http.StatusOK, listeners)
		})

		apiv1.DELETE("/listeners", func(c *gin.Context) {
			type ListenerDeleteRequest struct {
				ListenerID int
				AgentID    int
			}
			var listenerDeleteRequest ListenerDeleteRequest
			if err := c.ShouldBindJSON(&listenerDeleteRequest); err != nil {
				c.Error(err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			if _, ok := AgentList[listenerDeleteRequest.AgentID]; !ok {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid agent"})
				return
			}
			AgentList[listenerDeleteRequest.AgentID].DeleteListener(listenerDeleteRequest.ListenerID)
			c.JSON(http.StatusOK, gin.H{"message": "listener deleted"})
		})

		apiv1.POST("/listeners", func(c *gin.Context) {
			type ListenerRequest struct {
				AgentID      int
				ListenerAddr string
				RedirectAddr string
				Network      string
			}

			var listenerRequest ListenerRequest
			if err := c.ShouldBindJSON(&listenerRequest); err != nil {
				c.JSON(http.StatusInternalServerError, inputError)
				return
			}
			if _, ok := AgentList[listenerRequest.AgentID]; !ok {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid agent"})
				return
			}
			CurrentAgent := AgentList[listenerRequest.AgentID]
			proxyListener, err := CurrentAgent.AddListener(listenerRequest.ListenerAddr, listenerRequest.Network, listenerRequest.RedirectAddr)
			if err != nil {
				c.Error(err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			go func() {
				err := proxyListener.StartRelay()
				if err != nil {
					logrus.WithFields(logrus.Fields{"listener": proxyListener.String(), "agent": CurrentAgent.Name, "id": CurrentAgent.SessionID}).Error("Listener relay failed with error: ", err)
					return
				}

				logrus.WithFields(logrus.Fields{"listener": proxyListener.String(), "agent": CurrentAgent.Name, "id": CurrentAgent.SessionID}).Warning("Listener ended without error.")
				return
			}()

			c.JSON(http.StatusOK, gin.H{"message": "listener created"})
		})

		apiv1.GET("/agents", func(c *gin.Context) {
			c.IndentedJSON(http.StatusOK, AgentList)
		})

		apiv1.DELETE("/tunnel/:id", func(c *gin.Context) {
			tunnelParam := c.Param("id")
			tunnelId, err := strconv.Atoi(tunnelParam)
			if err != nil {
				c.JSON(http.StatusInternalServerError, inputError)
				return
			}
			if _, ok := AgentList[tunnelId]; !ok {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid agent"})
				return
			}
			CurrentAgent := AgentList[tunnelId]

			if CurrentAgent.Session == nil || !CurrentAgent.Running {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "tunnel not started"})
				return
			}
			CurrentAgent.CloseChan <- true
			CurrentAgent.Running = false
			c.JSON(http.StatusOK, gin.H{"message": "tunnel stopping"})
		})

		apiv1.POST("/tunnel/:id", func(c *gin.Context) {
			type TunnelStart struct {
				Interface string
			}
			var tunnelRequest TunnelStart
			tunnelParam := c.Param("id")
			tunnelId, err := strconv.Atoi(tunnelParam)
			if err != nil {
				c.JSON(http.StatusInternalServerError, inputError)
				return
			}
			if err := c.ShouldBindJSON(&tunnelRequest); err != nil {
				c.JSON(http.StatusInternalServerError, inputError)
				return
			}
			if _, ok := AgentList[tunnelId]; !ok {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid agent"})
				return
			}
			CurrentAgent := AgentList[tunnelId]
			if err := StartTunnel(CurrentAgent, tunnelRequest.Interface); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			c.JSON(http.StatusOK, gin.H{"message": "tunnel starting"})
		})
	}

	if config.Config.GetBool("web.tls.enabled") {
		// create tls config
		tlsConfig, err := tlsutils.CertManager(&tlsutils.CertManagerConfig{
			EnableAutocert:  config.Config.GetBool("web.tls.autocert"),
			DomainWhitelist: config.Config.GetStringSlice("web.tls.alloweddomains"),
			EnableSelfcert:  config.Config.GetBool("web.tls.selfcert"),
			SelfCertCache:   "ligolo-selfcerts",
			SelfcertDomain:  config.Config.GetString("web.tls.selfcertdomain"),
			Certfile:        config.Config.GetString("web.tls.certfile"),
			Keyfile:         config.Config.GetString("web.tls.keyfile"),
		})
		if err != nil {
			logrus.Fatal(err)
		}
		server := http.Server{
			Addr:      config.Config.GetString("web.listen"),
			Handler:   r,
			TLSConfig: tlsConfig,
		}
		// start tls server
		if err := server.ListenAndServeTLS("", ""); err != nil {
			logrus.Fatal(err)
		}
	} else {
		// listen and serve on 0.0.0.0:8080
		if err := r.Run(config.Config.GetString("web.listen")); err != nil {
			logrus.Fatal(err)
		}
	}
}

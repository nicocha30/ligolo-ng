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

package app

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/allsmog/ligolo-ng-relay/cmd/proxy/config"
	"github.com/allsmog/ligolo-ng-relay/pkg/proxy/netinfo"
	"github.com/allsmog/ligolo-ng-relay/pkg/tlsutils"
	"github.com/allsmog/ligolo-ng-relay/web"
	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/static"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
)

const (
	apiTokenTTL        = time.Hour
	loginFailureLimit  = 5
	loginFailureWindow = 5 * time.Minute
)

var (
	internalServerError = gin.H{"error": "internal server error"}
	inputError          = gin.H{"error": "input error"}
	apiLoginLimiter     = newLoginRateLimiter(loginFailureLimit, loginFailureWindow)
)

type loginRateLimiter struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	failures map[string]loginFailure
}

type loginFailure struct {
	count int
	first time.Time
}

func newLoginRateLimiter(limit int, window time.Duration) *loginRateLimiter {
	return &loginRateLimiter{
		limit:    limit,
		window:   window,
		failures: make(map[string]loginFailure),
	}
}

func (l *loginRateLimiter) TooManyFailures(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	failure, ok := l.failures[key]
	if !ok || now.Sub(failure.first) > l.window {
		delete(l.failures, key)
		return false
	}
	return failure.count >= l.limit
}

func (l *loginRateLimiter) RecordFailure(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()

	failure, ok := l.failures[key]
	if !ok || now.Sub(failure.first) > l.window {
		l.failures[key] = loginFailure{count: 1, first: now}
		return
	}
	failure.count++
	l.failures[key] = failure
}

func (l *loginRateLimiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, key)
}

func authorizationToken(header string) string {
	header = strings.TrimSpace(header)
	if len(header) >= len("Bearer ") && strings.EqualFold(header[:len("Bearer ")], "Bearer ") {
		return strings.TrimSpace(header[len("Bearer "):])
	}
	return header
}

func jwtSecret() []byte {
	return []byte(config.Config.GetString("web.secret"))
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := authorizationToken(c.GetHeader("Authorization"))
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}

		parser := jwt.NewParser(
			jwt.WithExpirationRequired(),
			jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		)
		token, err := parser.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret(), nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			c.Set("claims", claims)
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}

		c.Next()
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
	logrus.Warn("Ligolo-ng Relay API is enabled; keep it private or behind an authenticated reverse proxy.")

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
			c.JSON(http.StatusBadRequest, inputError)
			return
		}
		clientKey := c.ClientIP()
		now := time.Now()
		if apiLoginLimiter.TooManyFailures(clientKey, now) {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "too many failed login attempts"})
			return
		}
		if !config.CheckAuth(authInfo.Username, authInfo.Password) {
			apiLoginLimiter.RecordFailure(clientKey, now)
			c.Header("WWW-Authenticate", "Bearer")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}
		apiLoginLimiter.Reset(clientKey)
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"username": authInfo.Username,
			"role":     "admin",
			"iat":      now.Unix(),
			"exp":      now.Add(apiTokenTTL).Unix(),
		})
		signedJwt, err := token.SignedString(jwtSecret())
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

		apiv1.POST("/relay/:id", func(c *gin.Context) {
			type RelayRequest struct {
				ListenAddr      string
				AuthToken       string
				TokenTTLSeconds int64
				OneTimeToken    bool
			}
			var relayReq RelayRequest
			agentParam := c.Param("id")
			agentId, err := strconv.Atoi(agentParam)
			if err != nil {
				c.JSON(http.StatusBadRequest, inputError)
				return
			}
			if err := c.ShouldBindJSON(&relayReq); err != nil {
				c.JSON(http.StatusBadRequest, inputError)
				return
			}
			AgentListMutex.Lock()
			agent, ok := AgentList[agentId]
			AgentListMutex.Unlock()
			if !ok {
				c.JSON(http.StatusNotFound, gin.H{"error": "invalid agent"})
				return
			}
			if !agent.RelayCapable {
				c.JSON(http.StatusBadRequest, gin.H{"error": "agent does not support relay mode"})
				return
			}
			result, err := startRelayOnAgent(agent, relayReq.ListenAddr, relayReq.AuthToken, relayTokenTTLFromSeconds(relayReq.TokenTTLSeconds), relayReq.OneTimeToken)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			c.JSON(http.StatusOK, gin.H{
				"message":          "relay started",
				"fingerprint":      result.CertFingerprint,
				"auth_token":       result.AuthToken,
				"token_expires_at": result.TokenExpiresAt,
				"one_time_token":   result.OneTimeToken,
				"connect_command":  relayConnectCommand(relayReq.ListenAddr, result.CertFingerprint, result.AuthToken),
			})
		})

		apiv1.POST("/relay/:id/token", func(c *gin.Context) {
			type RelayTokenRequest struct {
				AuthToken       string
				TokenTTLSeconds int64
				OneTimeToken    bool
			}
			var req RelayTokenRequest
			agentParam := c.Param("id")
			agentId, err := strconv.Atoi(agentParam)
			if err != nil {
				c.JSON(http.StatusBadRequest, inputError)
				return
			}
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, inputError)
				return
			}
			AgentListMutex.Lock()
			agent, ok := AgentList[agentId]
			AgentListMutex.Unlock()
			if !ok {
				c.JSON(http.StatusNotFound, gin.H{"error": "invalid agent"})
				return
			}
			result, err := rotateRelayToken(agent, req.AuthToken, relayTokenTTLFromSeconds(req.TokenTTLSeconds), req.OneTimeToken)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			c.JSON(http.StatusOK, gin.H{
				"message":          "relay token rotated",
				"fingerprint":      result.CertFingerprint,
				"auth_token":       result.AuthToken,
				"token_expires_at": result.TokenExpiresAt,
				"one_time_token":   result.OneTimeToken,
				"connect_command":  relayConnectCommand(agent.RelayListenAddr, result.CertFingerprint, result.AuthToken),
			})
		})

		apiv1.DELETE("/relay/:id/token", func(c *gin.Context) {
			agentParam := c.Param("id")
			agentId, err := strconv.Atoi(agentParam)
			if err != nil {
				c.JSON(http.StatusBadRequest, inputError)
				return
			}
			AgentListMutex.Lock()
			agent, ok := AgentList[agentId]
			AgentListMutex.Unlock()
			if !ok {
				c.JSON(http.StatusNotFound, gin.H{"error": "invalid agent"})
				return
			}
			if err := stopRelayWithDownstream(agent); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			c.JSON(http.StatusOK, gin.H{"message": "relay token revoked and relay stopped"})
		})

		apiv1.DELETE("/relay/:id", func(c *gin.Context) {
			agentParam := c.Param("id")
			agentId, err := strconv.Atoi(agentParam)
			if err != nil {
				c.JSON(http.StatusBadRequest, inputError)
				return
			}
			AgentListMutex.Lock()
			agent, ok := AgentList[agentId]
			AgentListMutex.Unlock()
			if !ok {
				c.JSON(http.StatusNotFound, gin.H{"error": "invalid agent"})
				return
			}
			if err := stopRelayWithDownstream(agent); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			c.JSON(http.StatusOK, gin.H{"message": "relay stopped"})
		})

		apiv1.GET("/chains", func(c *gin.Context) {
			c.JSON(http.StatusOK, chainSnapshot())
		})

		apiv1.GET("/relay/doctor", func(c *gin.Context) {
			withIPv6, err := strconv.ParseBool(c.DefaultQuery("with_ipv6", "false"))
			if err != nil {
				c.JSON(http.StatusBadRequest, inputError)
				return
			}
			interfacePrefix := c.DefaultQuery("interface_prefix", "ligolo")
			c.JSON(http.StatusOK, relayDoctorReport(withIPv6, interfacePrefix))
		})

		apiv1.GET("/relay/ops", func(c *gin.Context) {
			withIPv6, err := strconv.ParseBool(c.DefaultQuery("with_ipv6", "false"))
			if err != nil {
				c.JSON(http.StatusBadRequest, inputError)
				return
			}
			interfacePrefix := c.DefaultQuery("interface_prefix", "ligolo")
			c.JSON(http.StatusOK, relayOpsReport(withIPv6, interfacePrefix))
		})

		apiv1.GET("/relay/autoheal", func(c *gin.Context) {
			c.JSON(http.StatusOK, RelayAutoHealStatusSnapshot())
		})

		apiv1.POST("/relay/autoheal/run", func(c *gin.Context) {
			var req RelayAutoHealRunRequest
			if c.Request.Body != nil && c.Request.ContentLength != 0 {
				if err := c.ShouldBindJSON(&req); err != nil {
					c.JSON(http.StatusBadRequest, inputError)
					return
				}
			}
			policy := relayAutoHealPolicyWithOverrides(relayAutoHealPolicyFromConfig(), req)
			run := RunRelayAutoHealOnce(policy)
			status := http.StatusOK
			if run.Status == "error" {
				status = http.StatusInternalServerError
			}
			c.JSON(status, run)
		})

		apiv1.GET("/chain_routes", func(c *gin.Context) {
			withIPv6, err := strconv.ParseBool(c.DefaultQuery("with_ipv6", "false"))
			if err != nil {
				c.JSON(http.StatusBadRequest, inputError)
				return
			}
			interfacePrefix := c.DefaultQuery("interface_prefix", "ligolo")
			c.JSON(http.StatusOK, gin.H{"routes": chainRouteInfos(withIPv6, interfacePrefix)})
		})

		apiv1.GET("/chain_route_plan", func(c *gin.Context) {
			withIPv6, err := strconv.ParseBool(c.DefaultQuery("with_ipv6", "false"))
			if err != nil {
				c.JSON(http.StatusBadRequest, inputError)
				return
			}
			start, err := strconv.ParseBool(c.DefaultQuery("start", "false"))
			if err != nil {
				c.JSON(http.StatusBadRequest, inputError)
				return
			}
			interfacePrefix := c.DefaultQuery("interface_prefix", "ligolo")
			c.JSON(http.StatusOK, chainRoutePlan(withIPv6, interfacePrefix, start))
		})

		apiv1.GET("/chain_repair_plan", func(c *gin.Context) {
			withIPv6, err := strconv.ParseBool(c.DefaultQuery("with_ipv6", "false"))
			if err != nil {
				c.JSON(http.StatusBadRequest, inputError)
				return
			}
			start, err := strconv.ParseBool(c.DefaultQuery("start", "false"))
			if err != nil {
				c.JSON(http.StatusBadRequest, inputError)
				return
			}
			pruneConflicts, err := strconv.ParseBool(c.DefaultQuery("prune_conflicts", "false"))
			if err != nil {
				c.JSON(http.StatusBadRequest, inputError)
				return
			}
			interfacePrefix := c.DefaultQuery("interface_prefix", "ligolo")
			c.JSON(http.StatusOK, chainRepairPlan(withIPv6, interfacePrefix, start, pruneConflicts))
		})

		apiv1.GET("/chain_failover_plan", func(c *gin.Context) {
			includeCommands, err := strconv.ParseBool(c.DefaultQuery("include_commands", "false"))
			if err != nil {
				c.JSON(http.StatusBadRequest, inputError)
				return
			}
			c.JSON(http.StatusOK, chainFailoverPlan(includeCommands))
		})

		apiv1.POST("/chain_failover", func(c *gin.Context) {
			type ChainFailoverRequest struct {
				IncludeCommands bool
				All             bool
				SessionIDs      []string
				AgentIDs        []int
			}
			var req ChainFailoverRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, inputError)
				return
			}
			if !req.All && len(req.SessionIDs) == 0 && len(req.AgentIDs) == 0 {
				c.JSON(http.StatusBadRequest, gin.H{"error": "chain failover apply requires All, SessionIDs, or AgentIDs"})
				return
			}
			plan := applyChainFailoverPlan(req.IncludeCommands, req.All, req.SessionIDs, req.AgentIDs)
			status := http.StatusOK
			if plan.Status == "error" {
				status = http.StatusInternalServerError
			}
			c.JSON(status, plan)
		})

		apiv1.POST("/chain_autoroute", func(c *gin.Context) {
			type ChainAutorouteRequest struct {
				WithIPv6        bool
				InterfacePrefix string
				Start           bool
			}
			var req ChainAutorouteRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, inputError)
				return
			}
			if req.InterfacePrefix == "" {
				req.InterfacePrefix = "ligolo"
			}
			routes, err := configureChainAutoroutes(req.WithIPv6, req.InterfacePrefix, req.Start)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			c.JSON(http.StatusOK, gin.H{
				"message": "chain autoroute configured",
				"routes":  routes,
				"plan":    chainRoutePlan(req.WithIPv6, req.InterfacePrefix, req.Start),
			})
		})

		apiv1.POST("/chain_repair", func(c *gin.Context) {
			type ChainRepairRequest struct {
				WithIPv6        bool
				InterfacePrefix string
				Start           bool
				PruneConflicts  bool
			}
			var req ChainRepairRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, inputError)
				return
			}
			if req.InterfacePrefix == "" {
				req.InterfacePrefix = "ligolo"
			}
			plan := applyChainRepairPlan(req.WithIPv6, req.InterfacePrefix, req.Start, req.PruneConflicts)
			status := http.StatusOK
			if plan.Status == "error" {
				status = http.StatusInternalServerError
			}
			c.JSON(status, plan)
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

	// Optionally serve the MCP control plane over streamable HTTP at /mcp,
	// behind the same JWT auth as /api/v1. Enabled with `-mcp-api`.
	if config.Config.GetBool("web.mcp") {
		mcpHandler := gin.WrapH(NewMCPHTTPHandler(config.Config.GetBool("web.mcpreadonly")))
		mcpGroup := r.Group("/mcp", authMiddleware())
		mcpGroup.Any("", mcpHandler)
		mcpGroup.Any("/*any", mcpHandler)
		logrus.Warn("MCP server mounted at /mcp (streamable HTTP, JWT-authenticated).")
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
		server := apiHTTPServer(config.Config.GetString("web.listen"), r)
		server.TLSConfig = tlsConfig
		// start tls server
		if err := server.ListenAndServeTLS("", ""); err != nil {
			logrus.Fatal(err)
		}
	} else {
		server := apiHTTPServer(config.Config.GetString("web.listen"), r)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logrus.Fatal(err)
		}
	}
}

func apiHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

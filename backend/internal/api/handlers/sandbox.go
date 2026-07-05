package handlers

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/analysishub/backend/internal/api/middleware"
	"github.com/analysishub/backend/internal/models"
)

// sandboxCookieName carries the JWT to the ttyd <iframe> and its sub-requests,
// which cannot set an Authorization header. It is HttpOnly + path-scoped so it
// only ever travels to the sandbox proxy and is invisible to JavaScript.
const sandboxCookieName = "fh_sandbox"

// sandboxCookieTTL bounds how long a granted terminal session stays valid
// without re-authenticating against the SPA.
const sandboxCookieTTL = 8 * time.Hour

// SandboxHandler reverse-proxies the authenticated admin to the internal
// volatility/kali ttyd web terminal. The sandbox container is NOT published on
// the host — it is reachable only on the compose network — so this proxy is the
// single entry point and every request through it is gated behind an admin JWT.
//
// The terminal doubles as an offensive toolbox (nmap, sqlmap, …); the sandbox
// container routes that tooling's egress through the integrated Tor SOCKS proxy
// (see volatility/Dockerfile + docker-compose) so scans never expose the host
// IP. This handler only governs *access* to the terminal, not its egress.
type SandboxHandler struct {
	proxy *httputil.ReverseProxy
}

// NewSandboxHandler builds the reverse proxy to the ttyd target (e.g.
// http://volatility_sandbox:7681). ttyd is launched with a matching
// --base-path so the forwarded path is passed through unchanged and the
// terminal's assets + WebSocket resolve correctly behind the proxy.
func NewSandboxHandler(targetURL string) (*SandboxHandler, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	rp := httputil.NewSingleHostReverseProxy(u)

	// Use a DEDICATED, clean transport — NOT the global http.DefaultTransport,
	// which main.go replaces with the egress-logging RoundTripper. That wrapper
	// records byte counts and therefore returns a non-hijackable response body
	// for a "101 Switching Protocols" upgrade, which breaks the ttyd WebSocket
	// ("101 switching protocols response with non-writable body"). Sandbox traffic
	// is internal (volatility_sandbox:7681) and must not be egress-recorded anyway.
	rp.Transport = &http.Transport{
		ForceAttemptHTTP2:     false, // WebSocket upgrades require HTTP/1.1
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}

	origDirector := rp.Director
	rp.Director = func(r *http.Request) {
		origDirector(r) // sets scheme/host + joins paths
		r.Host = u.Host
		// ttyd validates the Origin on the WebSocket upgrade; rewrite it to the
		// upstream so the same-origin check inside the container passes.
		if r.Header.Get("Upgrade") != "" {
			r.Header.Set("Origin", u.Scheme+"://"+u.Host)
		}
	}
	rp.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, e error) {
		log.Printf("[sandbox] proxy error: %v", e)
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("sandbox terminal unavailable"))
	}

	return &SandboxHandler{proxy: rp}, nil
}

// Proxy streams the request (HTTP assets + WebSocket) to ttyd. It must be
// mounted behind SandboxAuth.
func (h *SandboxHandler) Proxy(c *gin.Context) {
	h.proxy.ServeHTTP(c.Writer, c.Request)
}

// SandboxGrant drops the short-lived, path-scoped, HttpOnly cookie the iframe
// needs. It is mounted behind the normal AuthMiddleware (header/query token),
// so the caller is already authenticated here — we only enforce the admin role
// and copy the presented token into the cookie.
func SandboxGrant(c *gin.Context) {
	if middleware.GetRole(c) != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "admin role required"})
		return
	}

	token := bearerToken(c)
	if token == "" {
		token = c.Query("token")
	}
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "no token to grant"})
		return
	}

	// Mark the cookie Secure based on the BROWSER's actual scheme (not PUBLIC_URL):
	// a Secure cookie is dropped by the browser over plain http (localhost / LAN),
	// which would silently break the iframe auth. Honour the proxy's
	// X-Forwarded-Proto or a direct TLS connection.
	secure := c.Request.TLS != nil || strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https")
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(sandboxCookieName, token, int(sandboxCookieTTL.Seconds()), "/api/v1/sandbox/terminal", "", secure, true)
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// SandboxAuth gates the terminal proxy. It accepts the JWT from the
// Authorization header, the ?token= query param, or the fh_sandbox cookie (the
// iframe path), and requires the admin role — opening a root shell on the
// sandbox host must not be available to every authenticated user.
func SandboxAuth(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		c.Abort()
		return
	}
	jwtSecret := getJWTSecret(c)

	tokenStr := bearerToken(c)
	if tokenStr == "" {
		tokenStr = c.Query("token")
	}
	if tokenStr == "" {
		if ck, err := c.Cookie(sandboxCookieName); err == nil {
			tokenStr = ck
		}
	}
	if tokenStr == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"success": false, "error": "authentication required"})
		return
	}

	claims := &middleware.Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(jwtSecret), nil
	})
	if err != nil || !token.Valid {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"success": false, "error": "invalid or expired token"})
		return
	}
	if claims.Role != "admin" {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"success": false, "error": "admin role required"})
		return
	}

	var user models.User
	if err := db.First(&user, "id = ?", claims.UserID).Error; err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"success": false, "error": "user no longer exists"})
		return
	}

	c.Set(middleware.ContextUserID, claims.UserID)
	c.Set(middleware.ContextRole, claims.Role)
	c.Next()
}

// bearerToken extracts the token from a "Bearer <token>" Authorization header,
// or "" when absent/malformed.
func bearerToken(c *gin.Context) string {
	h := c.GetHeader("Authorization")
	if h == "" {
		return ""
	}
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}

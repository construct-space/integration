// Package middleware wires CORS, request logging, and gateway-derived
// auth onto the integration service mux.
package middleware

import (
	"log"
	"net/http"
	"strings"
	"time"

	"construct/integration/internal/config"
	"construct/integration/internal/gwauth"
)

// CORS applies the standard allow-list. Mirrors source / storage.
func CORS(cfg *config.Config) func(http.Handler) http.Handler {
	allowed := map[string]bool{}
	for _, o := range cfg.AllowedOrigins {
		allowed[o] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && allowed[origin] {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,PATCH,OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization,Content-Type,X-Internal-Secret,X-Auth-User-ID,X-Auth-Org-ID")
				w.Header().Set("Access-Control-Max-Age", "600")
				w.Header().Add("Vary", "Origin")
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Logger emits one line per request with method/path/status/duration.
func Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, sw.status, time.Since(start))
	})
}

// GatewayAuth requires a trusted X-Internal-Secret + non-empty
// X-Auth-User-ID. Used on user-facing /api/* routes that the source
// gateway forwards to.
func GatewayAuth(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !gwauth.Trusted(r, cfg.InternalSecret) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			userID := gwauth.HeaderUserID(r)
			if userID == "" {
				http.Error(w, "unauthorized: no user", http.StatusUnauthorized)
				return
			}
			r = gwauth.WithIdentity(r, userID, gwauth.HeaderOrgID(r))
			next.ServeHTTP(w, r)
		})
	}
}

// InternalOnly gates /internal/* — peer-service callers only, no user
// header required.
func InternalOnly(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !gwauth.Trusted(r, cfg.InternalSecret) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// TrimTrailingSlash makes "/api/foo/" behave like "/api/foo".
func TrimTrailingSlash(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.URL.Path) > 1 && strings.HasSuffix(r.URL.Path, "/") {
			r.URL.Path = strings.TrimRight(r.URL.Path, "/")
		}
		next.ServeHTTP(w, r)
	})
}

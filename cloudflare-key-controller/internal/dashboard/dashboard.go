// Package dashboard serves the local web UI for approving requests and
// watching keys.
//
// Authentication: the dashboard URL printed by `cfkey serve` carries a random
// secret in its #fragment. Fragments are never sent over the network; the
// page keeps the secret in localStorage (scoped to this exact origin,
// including the port) and sends it as a bearer header. Because the browser
// never attaches it automatically, other websites cannot forge requests
// (no CSRF), and agents that can reach localhost cannot act without it.
package dashboard

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"time"

	"cfkey/internal/broker"
)

//go:embed static
var static embed.FS

// Server is the dashboard HTTP server.
type Server struct {
	broker *broker.Broker
	secret string
	host   string // expected Host header, e.g. "localhost:7787"
	stop   func()
}

// New returns a dashboard for b. stop is called when the human presses
// "End session".
func New(b *broker.Broker, secret string, port string, stop func()) *Server {
	return &Server{broker: b, secret: secret, host: "localhost:" + port, stop: stop}
}

// Handler returns the dashboard's HTTP handler.
func (s *Server) Handler() http.Handler {
	files, _ := fs.Sub(static, "static")
	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServerFS(files))
	mux.HandleFunc("GET /api/state", s.auth(s.state))
	mux.HandleFunc("POST /api/requests/{id}/approve", s.auth(s.decide(true)))
	mux.HandleFunc("POST /api/requests/{id}/deny", s.auth(s.decide(false)))
	mux.HandleFunc("POST /api/keys/{id}/revoke", s.auth(s.revoke))
	mux.HandleFunc("POST /api/stop", s.auth(s.stopSession))
	return s.guard(mux)
}

// Serve listens on 127.0.0.1 only.
func (s *Server) Serve(ln net.Listener) error {
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	return srv.Serve(ln)
}

// guard rejects requests whose Host header is not ours (DNS rebinding) and
// sets restrictive security headers on every response.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		if r.Host != s.host {
			http.Error(w, "open the dashboard at http://"+s.host+"/", http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(s.secret)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized: open the dashboard link printed by `cfkey serve`"})
			return
		}
		next(w, r)
	}
}

func (s *Server) state(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"session":  s.broker.Session(),
		"requests": s.broker.Snapshot(),
		"now":      time.Now(),
	})
}

func (s *Server) decide(approve bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := s.broker.Decide(r.PathValue("id"), approve); err != nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
	}
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := s.broker.Revoke(ctx, r.PathValue("id")); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

func (s *Server) stopSession(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
	go s.stop()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

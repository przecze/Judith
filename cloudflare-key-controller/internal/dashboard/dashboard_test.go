package dashboard

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGuardAndAuth(t *testing.T) {
	s := &Server{secret: "s3cret", host: "localhost:7787", stop: func() {}}
	h := s.Handler()
	do := func(method, host, auth string) int {
		req := httptest.NewRequest(method, "http://"+host+"/api/stop", nil)
		req.Host = host
		if auth != "" {
			req.Header.Set("Authorization", "Bearer "+auth)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if c := do("POST", "evil.example:7787", "s3cret"); c != http.StatusMisdirectedRequest {
		t.Errorf("foreign Host: got %d", c)
	}
	if c := do("POST", "localhost:7787", ""); c != http.StatusUnauthorized {
		t.Errorf("no secret: got %d", c)
	}
	if c := do("POST", "localhost:7787", "wrong"); c != http.StatusUnauthorized {
		t.Errorf("wrong secret: got %d", c)
	}
	if c := do("POST", "localhost:7787", "s3cret"); c != http.StatusOK {
		t.Errorf("valid: got %d", c)
	}
	req := httptest.NewRequest("GET", "http://localhost:7787/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || rec.Header().Get("Content-Security-Policy") == "" {
		t.Errorf("index: %d, CSP %q", rec.Code, rec.Header().Get("Content-Security-Policy"))
	}
}

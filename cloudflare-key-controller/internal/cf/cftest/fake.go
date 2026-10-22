// Package cftest is an in-memory fake of the Cloudflare token API for tests.
package cftest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	"cfkey/internal/cf"
)

// Fake is a fake Cloudflare API.
type Fake struct {
	*httptest.Server
	Groups   []cf.PermissionGroup
	Accounts []cf.Account
	Zones    []cf.Zone

	mu     sync.Mutex
	tokens map[string]*cf.Token // by ID
	values map[string]string    // secret value -> ID
	next   int
}

// New starts a fake API with a master token (returned) holding policies.
func New(masterPolicies []cf.Policy) (*Fake, string) {
	f := &Fake{tokens: map[string]*cf.Token{}, values: map[string]string{}}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	master := f.Add(cf.Token{Name: "my master", Policies: masterPolicies})
	return f, master
}

// Add stores a token and returns its secret value.
func (f *Fake) Add(t cf.Token) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next++
	t.ID = fmt.Sprintf("tok%d", f.next)
	t.Status = "active"
	value := fmt.Sprintf("secret-%d", f.next)
	f.tokens[t.ID] = &t
	f.values[value] = t.ID
	return value
}

// Tokens returns copies of all live tokens.
func (f *Fake) Tokens() []cf.Token {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []cf.Token
	for i := 1; i <= f.next; i++ {
		if t, ok := f.tokens[fmt.Sprintf("tok%d", i)]; ok {
			out = append(out, *t)
		}
	}
	return out
}

// Token returns a token by name.
func (f *Fake) Token(name string) (cf.Token, bool) {
	for _, t := range f.Tokens() {
		if t.Name == name {
			return t, true
		}
	}
	return cf.Token{}, false
}

func (f *Fake) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	reply := func(status int, result any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		env := map[string]any{"success": status < 300, "errors": []any{}, "result": result}
		if status >= 300 {
			env["errors"] = []any{map[string]any{"code": 1000, "message": result}}
			env["result"] = nil
		}
		_ = json.NewEncoder(w).Encode(env)
	}
	id, ok := f.values[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
	if !ok {
		reply(401, "Invalid API Token")
		return
	}
	self := f.tokens[id]
	path := r.URL.Path
	switch {
	case r.Method == "GET" && path == "/user/tokens/verify":
		reply(200, map[string]string{"id": self.ID, "status": self.Status})
	case r.Method == "GET" && path == "/user/tokens/permission_groups":
		reply(200, f.Groups)
	case r.Method == "GET" && path == "/user/tokens":
		var out []cf.Token
		for _, t := range f.tokens {
			out = append(out, *t)
		}
		reply(200, out)
	case r.Method == "POST" && path == "/user/tokens":
		var t cf.Token
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil || t.Name == "" || len(t.Policies) == 0 {
			reply(400, "bad token")
			return
		}
		f.next++
		t.ID = fmt.Sprintf("tok%d", f.next)
		t.Status = "active"
		value := fmt.Sprintf("secret-%d", f.next)
		stored := t
		f.tokens[t.ID] = &stored
		f.values[value] = t.ID
		t.Value = value
		reply(200, t)
	case strings.HasPrefix(path, "/user/tokens/"):
		tid := strings.TrimPrefix(path, "/user/tokens/")
		t, ok := f.tokens[tid]
		if !ok {
			reply(404, "not found")
			return
		}
		if r.Method == "DELETE" {
			delete(f.tokens, tid)
			for v, i := range f.values {
				if i == tid {
					delete(f.values, v)
				}
			}
			reply(200, map[string]string{"id": tid})
			return
		}
		reply(200, t)
	case r.Method == "GET" && path == "/accounts":
		reply(200, f.Accounts)
	case r.Method == "GET" && path == "/zones":
		var out []cf.Zone
		for _, z := range f.Zones {
			if z.Name == r.URL.Query().Get("name") {
				out = append(out, z)
			}
		}
		reply(200, out)
	default:
		reply(404, "no route "+r.Method+" "+path)
	}
}

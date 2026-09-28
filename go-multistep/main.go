package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sync"
)

const controlToken = "zap-testbed-reset-v1"

var expected = []string{"/private", "/api/profile", "/api/orders", "/api/documents"}
var mu sync.Mutex
var tx = map[string]string{}
var sessions = map[string]string{}
var hits = map[string]int{}
var auth = map[string]int{"loginAttempts": 0, "successfulLogins": 0, "failedLogins": 0, "authenticatedRequests": 0, "unauthorizedRequests": 0}

func token() string { b := make([]byte, 16); _, _ = rand.Read(b); return hex.EncodeToString(b) }
func inc(k string)  { mu.Lock(); auth[k]++; mu.Unlock() }
func track(p string) {
	mu.Lock()
	for _, e := range expected {
		if p == e {
			hits[p]++
			break
		}
	}
	mu.Unlock()
}
func user(r *http.Request) string {
	c, e := r.Cookie("sid")
	if e != nil {
		return ""
	}
	mu.Lock()
	defer mu.Unlock()
	return sessions[c.Value]
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func coverage() map[string]any {
	mu.Lock()
	defer mu.Unlock()
	visited := []string{}
	missing := []string{}
	for _, p := range expected {
		if hits[p] > 0 {
			visited = append(visited, p)
		} else {
			missing = append(missing, p)
		}
	}
	a := map[string]int{}
	for k, v := range auth {
		a[k] = v
	}
	return map[string]any{"application": "go-multistep", "scenario": "multistep-cookie", "discovery": map[string]any{"expected": len(expected), "visited": len(visited), "coveragePercent": float64(len(visited)) * 100 / float64(len(expected)), "visitedEndpoints": visited, "missingEndpoints": missing}, "authentication": a}
}
func reset() {
	mu.Lock()
	defer mu.Unlock()
	hits = map[string]int{}
	for k := range auth {
		auth[k] = 0
	}
	tx = map[string]string{}
	sessions = map[string]string{}
}

var userPage = template.Must(template.New("u").Parse(`<!doctype html><html><body><h1>Go Multi-step Login</h1><form method="post" action="/login/username"><label>Username <input name="username" autocomplete="username"></label><button>Continue</button></form></body></html>`))
var passPage = template.Must(template.New("p").Parse(`<!doctype html><html><body><h1>Password step</h1><form method="post" action="/login/password"><input type="hidden" name="tx" value="{{.}}"><label>Password <input name="password" type="password" autocomplete="current-password"></label><button>Sign in</button></form></body></html>`))

func main() {
	http.HandleFunc("/__testbed/expected", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"application": "go-multistep", "expectedEndpoints": expected})
	})
	http.HandleFunc("/__testbed/coverage", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, coverage()) })
	http.HandleFunc("/__testbed/control/reset", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.Header.Get("X-Testbed-Control") != controlToken {
			writeJSON(w, 404, map[string]string{"error": "not found"})
			return
		}
		reset()
		writeJSON(w, 200, map[string]any{"reset": true, "application": "go-multistep"})
	})
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) { _ = userPage.Execute(w, nil) })
	http.HandleFunc("/login/username", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		inc("loginAttempts")
		_ = r.ParseForm()
		if r.Form.Get("username") != "zapuser" {
			inc("failedLogins")
			http.Error(w, "unknown user", 401)
			return
		}
		t := token()
		mu.Lock()
		tx[t] = "zapuser"
		mu.Unlock()
		_ = passPage.Execute(w, t)
	})
	http.HandleFunc("/login/password", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		_ = r.ParseForm()
		t := r.Form.Get("tx")
		mu.Lock()
		u := tx[t]
		delete(tx, t)
		mu.Unlock()
		if u != "zapuser" || r.Form.Get("password") != "ZapTest123!" {
			inc("failedLogins")
			http.Error(w, "bad credentials", 401)
			return
		}
		inc("successfulLogins")
		sid := token()
		mu.Lock()
		sessions[sid] = u
		mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: sid, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
		http.Redirect(w, r, "/private", 302)
	})
	http.HandleFunc("/private", func(w http.ResponseWriter, r *http.Request) {
		track("/private")
		u := user(r)
		if u == "" {
			inc("unauthorizedRequests")
			http.Redirect(w, r, "/login", 302)
			return
		}
		inc("authenticatedRequests")
		fmt.Fprintf(w, "<h1>AUTHENTICATED</h1><p>user=%s</p><p>technology=GO_MULTISTEP</p><ul><li><a href='/api/profile'>profile</a></li><li><a href='/api/orders'>orders</a></li><li><a href='/api/documents'>documents</a></li></ul>", u)
	})
	for _, p := range []string{"/api/profile", "/api/orders", "/api/documents"} {
		path := p
		http.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			track(path)
			u := user(r)
			if u == "" {
				inc("unauthorizedRequests")
				writeJSON(w, 401, map[string]any{"authenticated": false})
				return
			}
			inc("authenticatedRequests")
			writeJSON(w, 200, map[string]any{"authenticated": true, "username": u, "endpoint": path})
		})
	}
	http.HandleFunc("/api/whoami", func(w http.ResponseWriter, r *http.Request) {
		u := user(r)
		if u == "" {
			inc("unauthorizedRequests")
			writeJSON(w, 200, map[string]any{"authenticated": false, "technology": "GO_MULTISTEP"})
			return
		}
		inc("authenticatedRequests")
		writeJSON(w, 200, map[string]any{"authenticated": true, "username": u, "technology": "GO_MULTISTEP"})
	})
	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		if c, e := r.Cookie("sid"); e == nil {
			mu.Lock()
			delete(sessions, c.Value)
			mu.Unlock()
		}
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", Path: "/", MaxAge: -1})
		http.Redirect(w, r, "/login", 302)
	})
	_ = http.ListenAndServe(":8080", nil)
}

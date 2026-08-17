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

var mu sync.Mutex
var tx = map[string]string{}
var sessions = map[string]string{}

func token() string { b := make([]byte, 16); _, _ = rand.Read(b); return hex.EncodeToString(b) }
func user(r *http.Request) string {
	c, e := r.Cookie("sid")
	if e != nil {
		return ""
	}
	mu.Lock()
	defer mu.Unlock()
	return sessions[c.Value]
}

var userPage = template.Must(template.New("u").Parse(`<!doctype html><html><body><h1>Go Multi-step Login</h1><form method="post" action="/login/username"><label>Username <input name="username" autocomplete="username"></label><button>Continue</button></form></body></html>`))
var passPage = template.Must(template.New("p").Parse(`<!doctype html><html><body><h1>Password step</h1><form method="post" action="/login/password"><input type="hidden" name="tx" value="{{.}}"><label>Password <input name="password" type="password" autocomplete="current-password"></label><button>Sign in</button></form></body></html>`))

func main() {
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) { _ = userPage.Execute(w, nil) })
	http.HandleFunc("/login/username", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		_ = r.ParseForm()
		if r.Form.Get("username") != "zapuser" {
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
			http.Error(w, "bad credentials", 401)
			return
		}
		sid := token()
		mu.Lock()
		sessions[sid] = u
		mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: sid, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
		http.Redirect(w, r, "/private", 302)
	})
	http.HandleFunc("/private", func(w http.ResponseWriter, r *http.Request) {
		u := user(r)
		if u == "" {
			http.Redirect(w, r, "/login", 302)
			return
		}
		fmt.Fprintf(w, "<h1>AUTHENTICATED</h1><p>user=%s</p><p>technology=GO_MULTISTEP</p><a href='/api/whoami'>whoami</a>", u)
	})
	http.HandleFunc("/api/whoami", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		u := user(r)
		if u == "" {
			_ = json.NewEncoder(w).Encode(map[string]any{"authenticated": false, "technology": "GO_MULTISTEP"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"authenticated": true, "username": u, "technology": "GO_MULTISTEP"})
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

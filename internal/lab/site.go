package lab

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
)

// The hosts of Site.
const (
	SiteHost      = "lab.test"       // h2 and http/1.1
	SiteH1Host    = "h1.lab.test"    // http/1.1 only
	SitePlainHost = "plain.lab.test" // http://
)

// Site serves the page of the captures (cmd/labcapture) on SiteHost,
// SiteH1Host and SitePlainHost. Its loads cover the kinds of request a
// browser sends: navigation, stylesheet, script, image, fetch with and
// without a body, and a form post. The first answer sets a cookie, so the
// later requests carry one.
func Site() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "lab", Value: "1", Path: "/"})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!doctype html>
<html><head><meta charset="utf-8"><title>lab</title>
<link rel="stylesheet" href="/style.css">
<script src="/app.js" defer></script>
</head><body>
<h1>lab</h1>
<img src="/img.png" alt="">
<form method="post" action="/form"><input name="q" value="1"><button>post</button></form>
<p><a href="https://%s/">http/1.1 only</a> · <a href="http://%s/">http://</a> · <a href="https://%s/">h2</a></p>
</body></html>
`, SiteH1Host, SitePlainHost, SiteHost)
	})
	mux.HandleFunc("/style.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		io.WriteString(w, "body{font-family:sans-serif}\n")
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript")
		io.WriteString(w, `fetch("/data").then(r => r.text());
fetch("/api", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({a: 1})});
`)
	})
	mux.HandleFunc("/img.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write(pixel)
	})
	mux.HandleFunc("/form", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
	mux.HandleFunc("/data", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	})
	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	})
	return mux
}

// pixel is a 1x1 transparent PNG.
var pixel, _ = base64.StdEncoding.DecodeString(
	"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=")

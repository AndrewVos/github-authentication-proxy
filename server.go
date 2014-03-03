package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/dchest/authcookie"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"
)

var port string
var targetURI string
var organisation string
var clientID string
var clientSecret string
var cookieSecret []byte

func main() {
	port = os.Getenv("PORT")
	targetURI = os.Getenv("TARGET_URI")
	organisation = os.Getenv("ORGANISATION")
	clientID = os.Getenv("CLIENT_ID")
	clientSecret = os.Getenv("CLIENT_SECRET")
	cookieSecret = []byte(os.Getenv("COOKIE_SECRET"))

	target, _ := url.Parse(targetURI)
	proxy := httputil.NewSingleHostReverseProxy(target)
	http.HandleFunc("/", handler(proxy))
	err := http.ListenAndServe(":"+port, nil)
	if err != nil {
		panic(err)
	}
}

func handler(p *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_callback" {
			code := r.URL.Query().Get("code")
			accessToken, err := getAccessToken(code)
			if err != nil || accessToken == "" {
				http.Error(w, "Error authorizing with github", 500)
				return
			}
			if isUserInOrganisation(accessToken) {
				login(w, r)
				redirectURI, _ := r.Cookie("redirect_uri")
				http.Redirect(w, r, redirectURI.Value, 302)
				return
			} else {
				http.Error(w, "You are not in this organisation", 500)
				return
			}
		}
		if r.URL.Path != "/favicon.ico" && !authenticated(r) {
			http.SetCookie(w, &http.Cookie{Name: "redirect_uri", Value: r.URL.String()})
			http.Redirect(w, r, "https://github.com/login/oauth/authorize?scope=read:org&client_id="+clientID, 302)
			return
		}
		p.ServeHTTP(w, r)
	}
}

func login(w http.ResponseWriter, r *http.Request) {
	cookie := authcookie.NewSinceNow(organisation, 24*time.Hour, cookieSecret)
	http.SetCookie(w, &http.Cookie{Name: "token", Value: cookie})
}

func authenticated(r *http.Request) bool {
	cookie, err := r.Cookie("token")
	if err != nil {
		return false
	}
	return authcookie.Login(cookie.Value, cookieSecret) == organisation
}

func getAccessToken(code string) (string, error) {
	body, _ := json.Marshal(map[string]interface{}{
		"client_id":     clientID,
		"client_secret": clientSecret,
		"code":          code,
	})

	client := &http.Client{}
	request, _ := http.NewRequest("POST", "https://github.com/login/oauth/access_token", bytes.NewReader(body))

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}

	defer response.Body.Close()
	body, _ = ioutil.ReadAll(response.Body)
	var accessTokenResponse map[string]string
	json.Unmarshal(body, &accessTokenResponse)

	if token, ok := accessTokenResponse["access_token"]; ok {
		return token, nil
	}

	return "", errors.New("Error retrieving access token")
}

func isUserInOrganisation(accessToken string) bool {
	url := "https://api.github.com/orgs/" + organisation + "?access_token=" + accessToken
	response, err := http.Get(url)
	if err != nil {
		return false
	}
	if response.StatusCode == 200 {
		return true
	}
	return false
}

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
)

var port string
var targetURI string
var organisation string
var clientID string
var clientSecret string

func main() {
	port = os.Getenv("PORT")
	targetURI = os.Getenv("TARGET_URI")
	organisation = os.Getenv("ORGANISATION")
	clientID = os.Getenv("CLIENT_ID")
	clientSecret = os.Getenv("CLIENT_SECRET")

	target, _ := url.Parse(targetURI)
	proxy := httputil.NewSingleHostReverseProxy(target)
	http.HandleFunc("/", handler(proxy))
	err := http.ListenAndServe(":"+port, nil)
	if err != nil {
		panic(err)
	}
}

var logins = map[string]bool{}

func handler(p *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_callback" {
			code := r.URL.Query().Get("code")
			accessToken, err := getAccessToken(code)
			if err != nil || accessToken == "" {
				http.Error(w, "Error authorizing with github", 500)
				return
			}
			userOrganisations, err := getOrganisations(accessToken)
			if err != nil {
				http.Error(w, "Error listing user organisations", 500)
				return
			}
			for _, o := range userOrganisations {
				if o == organisation {
					token := randomLoginID()
					logins[token] = true
					http.SetCookie(w, &http.Cookie{Name: cookieName("token"), Value: token})
					redirectURI, _ := r.Cookie(cookieName("redirect_uri"))
					http.Redirect(w, r, redirectURI.Value, 302)
					return
				}
			}
			http.Error(w, "You are not in this organisation", 500)
			return
		}
		if authenticated(r) == false {
			http.SetCookie(w, &http.Cookie{Name: cookieName("redirect_uri"), Value: r.URL.String()})
			http.Redirect(w, r, "https://github.com/login/oauth/authorize?scope=read:org&client_id="+clientID, 302)
			return
		}
		p.ServeHTTP(w, r)
	}
}

func cookieName(name string) string {
	hostName, _ := os.Hostname()
	return name + "_" + hostName
}

func randomLoginID() string {
	b := make([]byte, 50)
	rand.Read(b)
	encoder := base64.URLEncoding
	token := make([]byte, encoder.EncodedLen(len(b)))
	encoder.Encode(token, b)
	t := fmt.Sprintf("%s", token)
	return t
}

func authenticated(r *http.Request) bool {
	cookie, err := r.Cookie(cookieName("token"))
	if err != nil {
		return false
	}
	return logins[cookie.Value] == true
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

func getOrganisations(accessToken string) ([]string, error) {
	response, err := http.Get("https://api.github.com/user/orgs?access_token=" + accessToken)
	if err != nil {
		return nil, err
	}

	var organisations []string

	defer response.Body.Close()
	b, _ := ioutil.ReadAll(response.Body)
	var userOrganisations []map[string]string
	json.Unmarshal(b, &userOrganisations)
	for _, userOrganisation := range userOrganisations {
		organisations = append(organisations, userOrganisation["login"])
	}

	return organisations, nil
}

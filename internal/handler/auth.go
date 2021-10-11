package handler

import (
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/danisbagus/golang-oauth2/internal/view"
	"github.com/danisbagus/golang-oauth2/pkg/logger"
	"golang.org/x/oauth2"
)

type AuthHandler struct {
	oauth2config     *oauth2.Config
	oauthStateString string
}

func NewAuthHandler(oauth2config *oauth2.Config, oauthStateString string) *AuthHandler {
	return &AuthHandler{
		oauth2config:     oauth2config,
		oauthStateString: oauthStateString,
	}
}

func (rc AuthHandler) MainView(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(view.IndexPage))
}

func (rc AuthHandler) LoginGoogle(w http.ResponseWriter, r *http.Request) {
	URL, err := url.Parse(rc.oauth2config.Endpoint.AuthURL)
	if err != nil {
		logger.Error("Parse: " + err.Error())
	}

	logger.Info(URL.String())
	parameters := url.Values{}
	parameters.Add("client_id", rc.oauth2config.ClientID)
	parameters.Add("scope", strings.Join(rc.oauth2config.Scopes, " "))
	parameters.Add("redirect_uri", rc.oauth2config.RedirectURL)
	parameters.Add("response_type", "code")
	parameters.Add("state", rc.oauthStateString)
	URL.RawQuery = parameters.Encode()
	url := URL.String()
	logger.Info(url)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (rc AuthHandler) CallbackFromGoole(w http.ResponseWriter, r *http.Request) {
	logger.Info("Callback from google")

	state := r.FormValue("state")
	logger.Info(state)

	if state != rc.oauthStateString {
		logger.Info("invalid oauth state")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	code := r.FormValue("code")
	logger.Info(code)

	if code == "" {
		logger.Warn("Code not found")
		w.Write([]byte("Code not found"))
		reason := r.FormValue("error_reason")
		if reason == "user_denied" {
			w.Write([]byte("User has denied permission"))
		}

	} else {
		token, err := rc.oauth2config.Exchange(oauth2.NoContext, code)
		if err != nil {
			logger.Error("Failed while do exchange: " + err.Error())
			return
		}
		logger.Info("Acces token: " + token.AccessToken)
		logger.Info("RefreshToken: " + token.RefreshToken)
		logger.Info("Expiration Time: " + token.Expiry.String())

		resp, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + url.QueryEscape(token.AccessToken))
		if err != nil {
			logger.Error("Failed while get response: " + err.Error())
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}
		defer resp.Body.Close()

		response, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			logger.Error("Failed while read all response: " + err.Error())
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		logger.Info("parseResponseBody: " + string(response))

		w.Write([]byte("User info from google:\n"))
		w.Write([]byte(string(response)))
		return
	}
}

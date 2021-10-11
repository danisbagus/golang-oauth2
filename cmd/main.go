package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/danisbagus/golang-oauth2/internal/handler"
	"github.com/spf13/viper"

	"github.com/gorilla/mux"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func main() {
	InitializeViper()

	appPort := viper.GetString("port")

	oauthConfGoogle := &oauth2.Config{
		ClientID:     viper.GetString("google.clientID"),
		ClientSecret: viper.GetString("google.clientSecret"),
		RedirectURL:  fmt.Sprintf("http://localhost:%s/callback-gl", appPort),
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}

	oauthStateStringGoogle := ""

	router := mux.NewRouter()

	AuthHandler := handler.NewAuthHandler(oauthConfGoogle, oauthStateStringGoogle)

	router.HandleFunc("/", AuthHandler.MainView)
	router.HandleFunc("/login-gl", AuthHandler.LoginGoogle)
	router.HandleFunc("/callback-gl", AuthHandler.CallbackFromGoole)

	server := new(http.Server)
	server.Handler = router
	server.Addr = fmt.Sprintf("0.0.0.0:%s", appPort)

	log.Println("Starting server at", server.Addr)
	err := server.ListenAndServe()
	if err != nil {
		log.Fatal(err.Error())
	}

}

func InitializeViper() {
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()
	viper.SetConfigType("yml")
	if err := viper.ReadInConfig(); err != nil {
		log.Fatal(fmt.Sprintf("Error while reading file %s", err))
	}
}

package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/lastlogin-net/decent-auth-go"
)

func main() {

	adminId := flag.String("admin-id", "", "Admin identifier")
	port := flag.Int("port", 3000, "Port")
	serverAddress := flag.String("server-address", "", "SMTP Server Address")
	serverPort := int16(*flag.Int("server-port", 587, "SMTP Server Port"))
	username := flag.String("username", "", "SMTP username")
	password := flag.String("password", "", "SMTP password")
	sender := flag.String("sender", "", "SMTP sender email")
	flag.Parse()

	authPrefix := "/auth"

	authHandler, err := decentauth.NewHandler(&decentauth.HandlerOptions{
		Config: decentauth.Config{
			PathPrefix: authPrefix,
			AdminID:    *adminId,
			LoginMethods: []decentauth.LoginMethod{
				decentauth.LoginMethod{
					Type: decentauth.LoginMethodQRCode,
				},
				decentauth.LoginMethod{
					Name: "LastLogin",
					URI:  "https://lastlogin.net",
					Type: decentauth.LoginMethodOIDC,
				},
				decentauth.LoginMethod{
					Type: decentauth.LoginMethodAdminCode,
				},
				decentauth.LoginMethod{
					Type: decentauth.LoginMethodATProto,
				},
				decentauth.LoginMethod{
					Type: decentauth.LoginMethodFediverse,
				},
				decentauth.LoginMethod{
					Type: decentauth.LoginMethodEmail,
				},
				decentauth.LoginMethod{
					Type: "FedCM",
				},
			},
			SMTPConfig: &decentauth.SMTPConfig{
				ServerAddress: *serverAddress,
				ServerPort:    serverPort,
				Username:      *username,
				Password:      *password,
				SenderEmail:   *sender,
			},
		},
	})
	exitOnError(err)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, authPrefix, 303)
	})

	http.Handle(authPrefix+"/", authHandler)

	fmt.Println("Running")
	err = http.ListenAndServe(fmt.Sprintf(":%d", *port), nil)
	exitOnError(err)
}

func exitOnError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}
}

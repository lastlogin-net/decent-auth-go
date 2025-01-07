package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/lastlogin-net/decent-auth-go"
)

const Template = "<h1>Logged in as %s</h1><a href='%s/logout'>Logout</a>"

func main() {

	authPrefix := "/auth"

	authHandler, err := decentauth.NewHandler(&decentauth.HandlerOptions{
		Config: decentauth.Config{
			PathPrefix: authPrefix,
			LoginMethods: []decentauth.LoginMethod{
				decentauth.LoginMethod{
					Type: "FedCM",
				},
			},
		},
	})
	exitOnError(err)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		session := authHandler.GetSession(r)

		if session == nil {
			http.Redirect(w, r, authPrefix, 303)
			return
		}

		w.Write([]byte(fmt.Sprintf(Template, session.Id, authPrefix)))
	})

	http.Handle(authPrefix+"/", authHandler)

	fmt.Println("Running")
	err = http.ListenAndServe(":3000", nil)
	exitOnError(err)
}

func exitOnError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}
}

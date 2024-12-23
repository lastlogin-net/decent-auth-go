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
	flag.Parse()

	authPrefix := "/auth"

	authHandler, err := decentauth.NewHandler(&decentauth.HandlerOptions{
		Config: decentauth.Config{
			PathPrefix: authPrefix,
			AdminID:    *adminId,
			LoginMethods: []decentauth.LoginMethod{
				decentauth.LoginMethod{
					Name: "Admin Code",
					Type: decentauth.LoginMethodAdminCode,
				},
				decentauth.LoginMethod{
					Name: "ATProto",
					Type: decentauth.LoginMethodATProto,
				},
				decentauth.LoginMethod{
					Name: "Fediverse",
					Type: decentauth.LoginMethodFediverse,
				},
			},
			OIDCProviders: []decentauth.OIDCProvider{
				decentauth.OIDCProvider{
					Name: "LastLogin",
					URI:  "https://lastlogin.net",
				},
				decentauth.OIDCProvider{
					Name: "Obligator",
					URI:  "https://auth.tn7.org",
				},
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

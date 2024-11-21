package main

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/lastlogin-net/decent-auth-go"
)

func buildHtml(session *decentauth.Session) string {
	return fmt.Sprintf(`
<!doctype html>
<html>
  <head>
  </head>
  <body>
    <h1>Logged in as %s</h1>
  </body>
</html>
`, session.Id)
}

func main() {

	authPrefix := "/auth"

	authHandler, err := decentauth.NewHandler(&decentauth.HandlerOptions{
		Prefix: authPrefix,
	})
	exitOnError(err)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		redirUrl := fmt.Sprintf("%s?return_path=%s", authPrefix, "/")

		session, err := authHandler.GetSession(r)
		if err != nil {
			http.Redirect(w, r, redirUrl, 303)
			return
		}

		io.WriteString(w, buildHtml(session))
	})

	//http.Handle(authPrefix+"/", http.StripPrefix(authPrefix, authHandler))
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

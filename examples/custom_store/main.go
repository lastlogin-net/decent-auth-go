package main

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/lastlogin-net/decent-auth-go"
	"github.com/philippgille/gokv/file"
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

	store, err := file.NewStore(file.Options{
		Directory: "./db",
	})
	exitOnError(err)

	authHandler, err := decentauth.NewHandler(&decentauth.HandlerOptions{
		Prefix:  authPrefix,
		KvStore: store,
	})
	exitOnError(err)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		session, redirected := authHandler.GetSessionOrLogin(w, r)
		if redirected {
			return
		}

		io.WriteString(w, buildHtml(session))
	})

	http.Handle(authPrefix+"/", http.StripPrefix(authPrefix, authHandler))

	fmt.Println("Running")
	http.ListenAndServe(":3000", nil)
}

func exitOnError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}
}

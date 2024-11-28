package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/lastlogin-net/decent-auth-go"
)

func buildHtml(id, returnTarget string) string {
	return fmt.Sprintf(`
<!doctype html>
<html>
  <head>
  </head>
  <body>
    <h1>Logged in as %s</h1>
    <a href='/protected'>Protected Page</a>
    <a href='/auth?return_target=%s'>Login</a>
    <a href='/auth/logout'>Logout</a>
  </body>
</html>
`, id, returnTarget)
}

func main() {

	adminId := flag.String("admin-id", "", "Admin identifier")
	flag.Parse()

	authPrefix := "/auth"

	authHandler, err := decentauth.NewHandler(&decentauth.HandlerOptions{
		Prefix:  authPrefix,
		AdminId: *adminId,
	})
	exitOnError(err)

	id := ""

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, buildHtml(id, r.URL.Path))
	})

	http.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {

		session := authHandler.GetSession(r)
		if session == nil {
			redirUrl := fmt.Sprintf("%s?return_target=%s", authPrefix, r.URL.Path)
			http.Redirect(w, r, redirUrl, 303)
			return
		}

		io.WriteString(w, buildHtml(session.Id, r.URL.Path))
	})

	//http.Handle(authPrefix+"/", http.StripPrefix(authPrefix, authHandler))
	http.Handle(authPrefix+"/", authHandler)
	http.Handle(authPrefix, authHandler)

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

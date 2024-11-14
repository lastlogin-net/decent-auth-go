package decentauth

import (
	"crypto/rand"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"math/big"
	"net/http"

	oauth "github.com/anderspitman/little-oauth2-go"
	"github.com/philippgille/gokv"
	"github.com/philippgille/gokv/gomap"
	//"github.com/philippgille/gokv/file"
)

//go:embed templates
var fs embed.FS

type Session struct {
	IdType string `json:"id_type"`
	Id     string `json:"id"`
}

type OIDCTokenResponse struct {
	oauth.TokenResponse
	IdToken string `json:"id_token"`
}

type Claims struct {
	Sub string `json:"sub"`
}

type Handler struct {
	mux   *http.ServeMux
	store gokv.Store
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

type HandlerOptions struct {
	Prefix  string
	KvStore gokv.Store
}

func NewHandler(opt *HandlerOptions) (h *Handler, err error) {

	var store gokv.Store

	if opt == nil || opt.KvStore == nil {
		store = gomap.NewStore(gomap.Options{})
		//store, err = file.NewStore(file.Options{
		//	Directory: "./db",
		//})
		//if err != nil {
		//	return
		//}
	} else {
		store = opt.KvStore
	}

	mux := http.NewServeMux()

	tmpl, err := template.ParseFS(fs, "templates/*")
	if err != nil {
		return
	}

	var flowState *oauth.AuthCodeFlowState

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		data := struct {
			AuthPrefix string
		}{
			AuthPrefix: opt.Prefix,
		}

		err = tmpl.ExecuteTemplate(w, "login.html", data)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	})

	mux.HandleFunc("/lastlogin", func(w http.ResponseWriter, r *http.Request) {

		ar := &oauth.AuthRequest{
			RedirectUri: fmt.Sprintf("http://localhost:3000%s/callback", opt.Prefix),
			Scopes:      []string{"openid profile"},
		}

		authUri := fmt.Sprintf("https://%s/auth", "lastlogin.net")
		flowState, err = oauth.StartAuthCodeFlow(authUri, ar)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		http.Redirect(w, r, flowState.AuthUri, 303)
	})

	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")

		tokenUri := fmt.Sprintf("https://%s/token", "lastlogin.net")
		resBytes, callbackErr := oauth.CompleteAuthCodeFlow(tokenUri, code, state, flowState)
		if callbackErr != nil {
			w.WriteHeader(500)
			io.WriteString(w, callbackErr.Error())
			return
		}

		var tokenRes *OIDCTokenResponse

		callbackErr = json.Unmarshal(resBytes, &tokenRes)
		if callbackErr != nil {
			w.WriteHeader(500)
			io.WriteString(w, callbackErr.Error())
			return
		}

		var claims Claims
		err := oauth.UnsafeParseJwt(tokenRes.IdToken, &claims)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		session := Session{
			IdType: "email",
			Id:     claims.Sub,
		}

		sessionKey, err := genRandomText(32)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		err = store.Set(fmt.Sprintf("sessions/%s", sessionKey), session)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "session_key",
			Value:    sessionKey,
			HttpOnly: true,
			Secure:   true,
			MaxAge:   86400,
			SameSite: http.SameSiteLaxMode,
			Path:     "/",
		})

		http.Redirect(w, r, "/", 303)
	})

	h = &Handler{
		mux:   mux,
		store: store,
	}

	return
}

func (h *Handler) GetSession(r *http.Request) (sess *Session, err error) {
	sessionCookie, err := r.Cookie("session_key")
	if err != nil {
		return
	}

	s := Session{}
	key := fmt.Sprintf("sessions/%s", sessionCookie.Value)
	found, err := h.store.Get(key, &s)
	if err != nil {
		return
	}

	if !found {
		err = errors.New("No such session")
		return
	}

	sess = &s
	return
}

func printJson(data interface{}) {
	d, _ := json.MarshalIndent(data, "", "  ")
	fmt.Println(string(d))
}

const chars string = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func genRandomText(length int) (string, error) {
	id := ""
	for i := 0; i < length; i++ {
		randIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", err
		}
		id += string(chars[randIndex.Int64()])
	}
	return id, nil
}

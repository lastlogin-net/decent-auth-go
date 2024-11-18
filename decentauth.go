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
	"net/url"
	"strings"

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

type oidcFlowState struct {
	OauthFlowState *oauth.AuthCodeFlowState `json:"oauth_flow_state"`
	ReturnTarget   string                   `json:"return_target"`
}

type loginCallback func(id string, w http.ResponseWriter, r *http.Request) (done bool, err error)

type Handler struct {
	PathPrefix    string
	mux           *http.ServeMux
	store         gokv.Store
	storagePrefix string
	loginCallback loginCallback
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

type HandlerOptions struct {
	Prefix  string
	KvStore gokv.Store
}

func NewHandler(opt *HandlerOptions) (h *Handler, err error) {

	storagePrefix := "decent_auth_"

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

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()

		returnTarget, err := getReturnTarget(r)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		data := struct {
			AuthPrefix   string
			ReturnTarget string
		}{
			AuthPrefix:   opt.Prefix,
			ReturnTarget: returnTarget,
		}

		err = tmpl.ExecuteTemplate(w, "login.html", data)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	})

	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()

		sessionCookieName := fmt.Sprintf("%ssession_key", h.storagePrefix)

		sessionCookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    "",
			HttpOnly: true,
			Secure:   true,
			MaxAge:   -1,
			SameSite: http.SameSiteLaxMode,
			Path:     "/",
		})

		err = store.Delete(fmt.Sprintf("%ssessions/%s", storagePrefix, sessionCookie.Value))
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		returnTarget, err := getReturnTarget(r)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		if returnTarget != "" {
			http.Redirect(w, r, returnTarget, 303)
		} else {
			http.Redirect(w, r, "/", 303)
		}
	})

	mux.HandleFunc("/lastlogin", func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()

		redirectUri := fmt.Sprintf("https://%s%s/callback", r.Host, opt.Prefix)

		ar := &oauth.AuthRequest{
			RedirectUri: redirectUri,
			Scopes:      []string{"openid profile"},
		}

		authUri := fmt.Sprintf("https://%s/auth", "lastlogin.net")
		fs, err := oauth.StartAuthCodeFlow(authUri, ar)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		returnTarget, err := getReturnTarget(r)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		flowState := oidcFlowState{
			OauthFlowState: fs,
			ReturnTarget:   returnTarget,
		}

		key := fmt.Sprintf("%soidc_flow_state/%s", storagePrefix, fs.State)
		err = store.Set(key, flowState)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		http.Redirect(w, r, fs.AuthUri, 303)
	})

	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")

		key := fmt.Sprintf("%soidc_flow_state/%s", storagePrefix, state)
		var flowState oidcFlowState
		found, err := h.store.Get(key, &flowState)
		if err != nil {
			return
		}

		if !found {
			err = errors.New("No such flow state")
			return
		}

		err = store.Delete(fmt.Sprintf("%soidc_flow_state/%s", storagePrefix, state))
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		tokenUri := fmt.Sprintf("https://%s/token", "lastlogin.net")
		fs := flowState.OauthFlowState
		resBytes, callbackErr := oauth.CompleteAuthCodeFlow(tokenUri, code, state, fs)
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
		err = oauth.UnsafeParseJwt(tokenRes.IdToken, &claims)
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

		err = store.Set(fmt.Sprintf("%ssessions/%s", storagePrefix, sessionKey), session)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		sessionCookieName := fmt.Sprintf("%ssession_key", storagePrefix)

		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    sessionKey,
			HttpOnly: true,
			Secure:   true,
			MaxAge:   86400,
			SameSite: http.SameSiteLaxMode,
			Path:     "/",
		})

		http.Redirect(w, r, flowState.ReturnTarget, 303)
	})

	h = &Handler{
		PathPrefix:    opt.Prefix,
		mux:           mux,
		store:         store,
		storagePrefix: storagePrefix,
	}

	return
}

func (h *Handler) LoginCallback(callback loginCallback) {
	h.loginCallback = callback
}

func (h *Handler) GetSessionOrLogin(w http.ResponseWriter, r *http.Request) (sess *Session, done bool) {
	sess, err := h.GetSession(r)
	if err != nil {
		h.LoginRedirect(w, r)
		done = true
		return
	}

	return
}

func (h *Handler) GetSession(r *http.Request) (sess *Session, err error) {
	sessionCookieName := fmt.Sprintf("%ssession_key", h.storagePrefix)
	sessionCookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return
	}

	s := Session{}
	key := fmt.Sprintf("%ssessions/%s", h.storagePrefix, sessionCookie.Value)
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

func (h *Handler) LoginRedirect(w http.ResponseWriter, r *http.Request) {
	returnTarget := url.QueryEscape(fmt.Sprintf("%s?%s", r.URL.Path, r.URL.RawQuery))
	http.Redirect(w, r, h.PathPrefix+"?return_target="+returnTarget, 303)
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

func getReturnTarget(r *http.Request) (string, error) {
	r.ParseForm()
	rt := r.Form.Get("return_target")

	if rt == "" {
		return rt, nil
	}

	if !strings.HasPrefix(rt, "/") {
		return "", errors.New("return_target must start with /")
	}

	return rt, nil
}

package decentauth

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"strings"

	"github.com/extism/go-sdk"
	"github.com/tetratelabs/wazero"
)

//go:embed decentauth.wasm
var fs embed.FS

const ErrorCodeNoError = 0

type HttpRequest struct {
	Url     string      `json:"url"`
	Headers http.Header `json:"headers"`
	Method  string      `json:"method"`
	Body    string      `json:"body"`
}

type HttpResponse struct {
	Code    int         `json:"code"`
	Headers http.Header `json:"headers"`
	Body    string      `json:"body"`
}

type Session struct {
	IdType string `json:"id_type"`
	Id     string `json:"id"`
}

type EmailMessage struct {
	From    string `json:"from"`
	To      string `json:"to"`
	Subject string `json:"subject"`
	Text    string `json:"text"`
}

type loginCallback func(id string, w http.ResponseWriter, r *http.Request) (done bool, err error)

type Handler struct {
	PathPrefix     string
	mux            *http.ServeMux
	store          KvStore
	storagePrefix  string
	loginCallback  loginCallback
	compiledPlugin *extism.CompiledPlugin
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

type HandlerOptions struct {
	KvStore KvStore
	Config  Config
}

type Config struct {
	PathPrefix    string        `json:"path_prefix,omitempty"`
	StoragePrefix string        `json:"storage_prefix,omitempty"`
	AdminID       string        `json:"admin_id"`
	IDHeaderName  string        `json:"id_header_name"`
	LoginMethods  []LoginMethod `json:"login_methods"`
	SMTPConfig    *SMTPConfig   `json:"smtp_config"`
}

type LoginMethod struct {
	Type LoginMethodType `json:"type"`
	Name string          `json:"name,omitempty" db"name"`
	URI  string          `json:"uri,omitempty" db"uri"`
}

type SMTPConfig struct {
	ServerAddress string `json:"server_address"`
	ServerPort    int16  `json:"server_port"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	SenderEmail   string `json:"sender_email"`
}

type LoginMethodType string

const (
	LoginMethodOIDC      = "OIDC"
	LoginMethodAdminCode = "Admin Code"
	LoginMethodATProto   = "ATProto"
	LoginMethodFediverse = "Fediverse"
	LoginMethodEmail     = "Email"
)

func NewHandler(opt *HandlerOptions) (h *Handler, err error) {

	storagePrefix := "decentauth"

	var store KvStore

	if opt == nil || opt.KvStore == nil {
		//store = NewMemoryKvStore()
		store, err = NewSqliteKvStore()
		if err != nil {
			return
		}
	} else {
		store = opt.KvStore
	}

	kvRead := extism.NewHostFunctionWithStack(
		"kv_read",
		func(ctx context.Context, p *extism.CurrentPlugin, stack []uint64) {

			returnError := func(code uint8) {
				fmt.Println("error code", code)
				stack[0], err = p.WriteBytes([]byte{code})
				if err != nil {
					panic(err)
				}
			}

			key, err := p.ReadString(stack[0])
			if err != nil {
				returnError(1)
				return
			}

			valueBytes, err := store.Get(key)
			if err != nil {
				returnError(2)
				return
			}

			valueBytes = append([]byte{ErrorCodeNoError}, valueBytes...)
			stack[0], err = p.WriteBytes(valueBytes)
			if err != nil {
				panic(err)
			}
		},
		[]extism.ValueType{extism.ValueTypePTR},
		[]extism.ValueType{extism.ValueTypePTR},
	)

	kvWrite := extism.NewHostFunctionWithStack(
		"kv_write",
		func(ctx context.Context, p *extism.CurrentPlugin, stack []uint64) {
			key, err := p.ReadString(stack[0])
			if err != nil {
				panic(err)
			}

			valueBytes, err := p.ReadBytes(stack[1])
			if err != nil {
				panic(err)
			}

			err = store.Set(key, valueBytes)
			if err != nil {
				panic(err)
			}
		},
		[]extism.ValueType{extism.ValueTypePTR, extism.ValueTypePTR},
		[]extism.ValueType{},
	)

	kvDelete := extism.NewHostFunctionWithStack(
		"kv_delete",
		func(ctx context.Context, p *extism.CurrentPlugin, stack []uint64) {
			key, err := p.ReadString(stack[0])
			if err != nil {
				panic(err)
			}

			err = store.Delete(key)
			if err != nil {
				panic(err)
			}
		},
		[]extism.ValueType{extism.ValueTypePTR},
		[]extism.ValueType{},
	)

	kvList := extism.NewHostFunctionWithStack(
		"kv_list",
		func(ctx context.Context, p *extism.CurrentPlugin, stack []uint64) {

			returnError := func(code uint8) {
				fmt.Println("error code", code)
				stack[0], err = p.WriteBytes([]byte{code})
				if err != nil {
					panic(err)
				}
			}

			prefix, err := p.ReadString(stack[0])
			if err != nil {
				returnError(1)
				return
			}

			keys, err := store.List(prefix)
			if err != nil {
				returnError(2)
				return
			}

			var keysJson []byte
			if len(keys) > 0 {
				keysJson, err = json.Marshal(keys)
				if err != nil {
					returnError(3)
					return
				}
			} else {
				keysJson = []byte("[]")
			}

			valueBytes := append([]byte{ErrorCodeNoError}, keysJson...)
			stack[0], err = p.WriteBytes(valueBytes)
			if err != nil {
				panic(err)
			}
		},
		[]extism.ValueType{extism.ValueTypePTR},
		[]extism.ValueType{extism.ValueTypePTR},
	)

	sendEmail := extism.NewHostFunctionWithStack(
		"extism_send_email",
		func(ctx context.Context, p *extism.CurrentPlugin, stack []uint64) {

			if opt.Config.SMTPConfig == nil {
				fmt.Println("No SMTP config")
				return
			}

			emailJson, err := p.ReadBytes(stack[0])
			if err != nil {
				fmt.Println(err)
				return
			}

			var msg EmailMessage

			err = json.Unmarshal(emailJson, &msg)
			if err != nil {
				fmt.Println(err)
				return
			}

			username := opt.Config.SMTPConfig.Username
			password := opt.Config.SMTPConfig.Password
			server := opt.Config.SMTPConfig.ServerAddress
			auth := smtp.PlainAuth("", username, password, server)

			bodyTemplate := "From: %s\r\n" +
				"To: %s\r\n" +
				"Subject: %s\r\n" +
				"\r\n" +
				"%s" +
				"\r\n"
			body := fmt.Sprintf(bodyTemplate, msg.From, msg.To, msg.Subject, msg.Text)

			addr := fmt.Sprintf("%s:%d", server, opt.Config.SMTPConfig.ServerPort)

			go func() {
				err = smtp.SendMail(addr, auth, msg.From, []string{msg.To}, []byte(body))
				if err != nil {
					fmt.Println(err)
					return
				}
			}()
		},
		[]extism.ValueType{extism.ValueTypePTR},
		[]extism.ValueType{},
	)

	//extism.SetLogLevel(extism.LogLevelDebug)
	extism.SetLogLevel(extism.LogLevelInfo)

	wasmFile, err := fs.Open("decentauth.wasm")
	if err != nil {
		return
	}

	wasmBytes, err := io.ReadAll(wasmFile)
	if err != nil {
		return
	}

	//_, curFilePath, _, ok := runtime.Caller(0)
	//if !ok {
	//	err = errors.New("runtime.Caller failed")
	//	return
	//}

	//dir := filepath.Dir(curFilePath)
	//wasmPath := filepath.Join(dir, "decentauth.wasm")

	configBytes, err := json.Marshal(opt.Config)
	if err != nil {
		return
	}

	manifest := extism.Manifest{
		Wasm: []extism.Wasm{
			//extism.WasmFile{
			//	Path: wasmPath,
			//},
			extism.WasmData{
				Data: wasmBytes,
			},
		},
		AllowedHosts: []string{"*"},
		//AllowedPaths: map[string]string{
		//	"./": "/",
		//},
		Config: map[string]string{
			"config": string(configBytes),
		},
	}

	ctx := context.Background()
	config := extism.PluginConfig{
		EnableWasi:                true,
		EnableHttpResponseHeaders: true,
	}
	hostFunctions := []extism.HostFunction{
		kvRead,
		kvWrite,
		kvDelete,
		kvList,
		sendEmail,
	}
	compiledPlugin, err := extism.NewCompiledPlugin(ctx, manifest, config, hostFunctions)
	if err != nil {
		return
	}

	moduleConfig := createModuleConfig()

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		pluginInstanceConfig := extism.PluginInstanceConfig{
			ModuleConfig: moduleConfig,
		}

		plugin, err := compiledPlugin.Instance(ctx, pluginInstanceConfig)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer plugin.Close(ctx)

		jsonBytes, err := encodePluginReq(r)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		_, resJson, err := plugin.Call("extism_handle", jsonBytes)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		var res HttpResponse

		err = json.Unmarshal(resJson, &res)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		for key, values := range res.Headers {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}

		w.WriteHeader(res.Code)
		w.Write([]byte(res.Body))
	})

	h = &Handler{
		PathPrefix:     opt.Config.PathPrefix,
		mux:            mux,
		store:          store,
		storagePrefix:  storagePrefix,
		compiledPlugin: compiledPlugin,
	}

	return
}

func (h *Handler) LoginCallback(callback loginCallback) {
	h.loginCallback = callback
}

func (h *Handler) GetSessionOrLogin(w http.ResponseWriter, r *http.Request) (sess *Session, done bool) {
	sess = h.GetSession(r)
	if sess == nil {
		h.LoginRedirect(w, r)
		done = true
		return
	}

	return
}

func (h *Handler) GetSession(r *http.Request) (sess *Session) {

	return h.getSession(r)

	//sessionCookieName := fmt.Sprintf("%s_session_key", h.storagePrefix)
	//sessionCookie, err := r.Cookie(sessionCookieName)
	//if err != nil {
	//	return
	//}

	//s := Session{}
	//key := fmt.Sprintf("/%s/sessions/%s", h.storagePrefix, sessionCookie.Value)
	//valueBytes, err := h.store.Get(key)
	//if err != nil {
	//	return
	//}

	//err = json.Unmarshal(valueBytes, &s)
	//if err != nil {
	//	return
	//}

	//sess = &s
	//return
}

func (h *Handler) LoginRedirect(w http.ResponseWriter, r *http.Request) {
	returnTarget := url.QueryEscape(fmt.Sprintf("%s?%s", r.URL.Path, r.URL.RawQuery))
	http.Redirect(w, r, h.PathPrefix+"?return_target="+returnTarget, 303)
}

func (h *Handler) getSession(r *http.Request) (session *Session) {

	moduleConfig := createModuleConfig()

	pluginInstanceConfig := extism.PluginInstanceConfig{
		ModuleConfig: moduleConfig,
	}

	ctx := context.Background()

	plugin, err := h.compiledPlugin.Instance(ctx, pluginInstanceConfig)
	if err != nil {
		return
	}
	defer plugin.Close(ctx)

	jsonBytes, err := encodePluginReq(r)
	if err != nil {
		return
	}

	_, resJson, err := plugin.Call("extism_get_session", jsonBytes)
	if err != nil {
		return
	}

	var res Session

	err = json.Unmarshal(resJson, &res)
	if err != nil {
		return
	}

	if res.Id == "" {
		return nil
	}

	session = &res

	return
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

func encodePluginReq(r *http.Request) (jsonBytes []byte, err error) {
	// TODO: should we be passing in the auth prefix as well?
	uri := fmt.Sprintf("http://%s%s", r.Host, r.URL.RequestURI())

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return
	}
	r.Body.Close()

	headers := make(map[string][]string)

	for key, value := range r.Header {
		headers[strings.ToLower(key)] = value
	}

	req := &HttpRequest{
		Url:     uri,
		Headers: headers,
		Method:  r.Method,
		Body:    string(body),
	}

	jsonBytes, err = json.Marshal(req)
	if err != nil {
		return
	}

	return
}

func createModuleConfig() wazero.ModuleConfig {
	moduleConfig := wazero.NewModuleConfig().
		WithSysWalltime().
		WithSysNanotime().
		WithSysNanosleep().
		WithRandSource(rand.Reader).
		WithStderr(os.Stderr).
		WithStdout(os.Stdout)
	return moduleConfig
}

func printJson(data interface{}) {
	d, _ := json.MarshalIndent(data, "", "  ")
	fmt.Println(string(d))
}

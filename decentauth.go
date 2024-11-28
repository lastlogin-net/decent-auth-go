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
	"net/url"
	"strings"

	"github.com/extism/go-sdk"
	"github.com/tetratelabs/wazero"
)

//go:embed decent_auth.wasm
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
	Prefix  string
	KvStore KvStore
	AdminId string
}

func NewHandler(opt *HandlerOptions) (h *Handler, err error) {

	storagePrefix := "decent_auth"

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

	extism.SetLogLevel(extism.LogLevelDebug)
	//extism.SetLogLevel(extism.LogLevelInfo)

	wasmFile, err := fs.Open("decent_auth.wasm")
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
	//wasmPath := filepath.Join(dir, "decent_auth.wasm")

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
		Config: map[string]string{
			"path_prefix":    opt.Prefix,
			"storage_prefix": storagePrefix,
			"admin_id":       opt.AdminId,
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
	}
	compiledPlugin, err := extism.NewCompiledPlugin(ctx, manifest, config, hostFunctions)
	if err != nil {
		return
	}

	moduleConfig := wazero.NewModuleConfig().
		WithSysWalltime().
		WithSysNanotime().
		WithSysNanosleep().
		WithRandSource(rand.Reader)

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		pluginInstanceConfig := extism.PluginInstanceConfig{
			ModuleConfig: moduleConfig,
		}

		plugin, err := compiledPlugin.Instance(ctx, pluginInstanceConfig)
		if err != nil {
			return
		}

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
		PathPrefix:     opt.Prefix,
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

	moduleConfig := wazero.NewModuleConfig().
		WithSysWalltime().
		WithSysNanotime().
		WithSysNanosleep().
		WithRandSource(rand.Reader)

	pluginInstanceConfig := extism.PluginInstanceConfig{
		ModuleConfig: moduleConfig,
	}

	plugin, err := h.compiledPlugin.Instance(context.Background(), pluginInstanceConfig)
	if err != nil {
		return
	}

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

func printJson(data interface{}) {
	d, _ := json.MarshalIndent(data, "", "  ")
	fmt.Println(string(d))
}

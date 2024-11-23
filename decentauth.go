package decentauth

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/philippgille/gokv"
	//"github.com/philippgille/gokv/gomap"
	"github.com/extism/go-sdk"
	"github.com/philippgille/gokv/file"
)

//go:embed decent_auth_rs.wasm
var fs embed.FS

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

	storagePrefix := "decent_auth"

	var store gokv.Store

	if opt == nil || opt.KvStore == nil {
		//store = gomap.NewStore(gomap.Options{})
		store, err = file.NewStore(file.Options{
			Directory: "./db",
		})
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

			var value any
			found, err := store.Get(key, &value)
			if err != nil {
				returnError(2)
				return
			}
			if !found {
				returnError(3)
				return
			}

			// TODO: see if we can avoid duplicate JSON encoding. It would probably require
			// having a method on the KV for storing pre-encoded data, like SetEncoded() or
			// something
			bytes, err := json.Marshal(value)
			if err != nil {
				returnError(4)
				return
			}

			bytes = append([]byte{65}, bytes...)
			stack[0], err = p.WriteBytes(bytes)
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

			value, err := p.ReadBytes(stack[1])
			if err != nil {
				panic(err)
			}

			var data any
			err = json.Unmarshal(value, &data)
			if err != nil {
				panic(err)
			}

			err = store.Set(key, data)
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

	wasmFile, err := fs.Open("decent_auth_rs.wasm")
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
	//wasmPath := filepath.Join(dir, "decent_auth_rs.wasm")

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
		},
	}

	mut := &sync.Mutex{}

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
	plugin, err := extism.NewPlugin(ctx, manifest, config, hostFunctions)
	if err != nil {
		return
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		// TODO: should we be passing in the auth prefix as well?
		uri := fmt.Sprintf("http://%s%s", r.Host, r.URL.RequestURI())

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		r.Body.Close()

		req := HttpRequest{
			Url:     uri,
			Headers: r.Header,
			Method:  r.Method,
			Body:    string(body),
		}

		jsonBytes, err := json.Marshal(req)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		mut.Lock()
		_, resJson, err := plugin.Call("handle", jsonBytes)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		mut.Unlock()

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
	sessionCookieName := fmt.Sprintf("%s_session_key", h.storagePrefix)
	sessionCookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return
	}

	s := Session{}
	key := fmt.Sprintf("/%s/sessions/%s", h.storagePrefix, sessionCookie.Value)
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

func printJson(data interface{}) {
	d, _ := json.MarshalIndent(data, "", "  ")
	fmt.Println(string(d))
}

package stakerservice

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"regexp"
	"sort"
	"strings"

	cmtjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/rpc/jsonrpc/server"
	types "github.com/cometbft/cometbft/rpc/jsonrpc/types"
)

// https://github.com/cometbft/cometbft/blob/38a4caeac0551c188af8a3e209e48380cd514e2d/rpc/jsonrpc/server/rpc_func.go#L1
// This file was mostly coppied from cometbft just to add a middleware in the RPC routes.
// The middleware used was to add basic auth to routes with user and password

var reInt = regexp.MustCompile(`^-?[0-9]+$`)

// RPCFunc contains the introspected type information for a function
type RPCFunc struct {
	f              reflect.Value          // underlying rpc function
	args           []reflect.Type         // type of each function arg
	returns        []reflect.Type         // type of each return arg
	argNames       []string               // name of each argument
	cacheable      bool                   // enable cache control
	ws             bool                   // enable websocket communication
	noCacheDefArgs map[string]interface{} // a lookup table of args that, if not supplied or are set to default values, cause us to not cache
}

type Option func(*RPCFunc)

// RegisterRPCFuncs adds a route for each function in the funcMap, as well as
// general jsonrpc and websocket handlers for all functions. "result" is the
// interface on which the result objects are registered, and is popualted with
// every RPCResponse
func RegisterRPCFuncs(mux *http.ServeMux, funcMap map[string]*RPCFunc, logger log.Logger, middleware func(http.HandlerFunc) http.HandlerFunc) {
	// HTTP endpoints
	for funcName, rpcFunc := range funcMap {
		rpcHandler := makeHTTPHandler(rpcFunc, logger)
		mux.HandleFunc("/"+funcName, middleware(rpcHandler))
	}

	// JSONRPC endpoints
	mux.HandleFunc("/", handleInvalidJSONRPCPaths(makeJSONRPCHandler(funcMap, logger)))
}

func handleInvalidJSONRPCPaths(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Since the pattern "/" matches all paths not matched by other registered patterns,
		//  we check whether the path is indeed "/", otherwise return a 404 error
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		next(w, r)
	}
}

// convert from a function name to the http handler
func makeHTTPHandler(rpcFunc *RPCFunc, logger log.Logger) func(http.ResponseWriter, *http.Request) {
	// Always return -1 as there's no ID here.
	dummyID := types.JSONRPCIntID(-1) // URIClientRequestID

	// Exception for websocket endpoints
	if rpcFunc.ws {
		return func(w http.ResponseWriter, r *http.Request) {
			res := types.RPCMethodNotFoundError(dummyID)
			if wErr := server.WriteRPCResponseHTTPError(w, http.StatusNotFound, res); wErr != nil {
				logger.Error("failed to write response", "err", wErr)
			}
		}
	}

	// All other endpoints
	return func(w http.ResponseWriter, r *http.Request) {
		logger.Debug("HTTP HANDLER", "req", r)

		ctx := &types.Context{HTTPReq: r}
		args := []reflect.Value{reflect.ValueOf(ctx)}

		fnArgs, err := httpParamsToArgs(rpcFunc, r)
		if err != nil {
			res := types.RPCInvalidParamsError(dummyID,
				fmt.Errorf("error converting http params to arguments: %w", err),
			)
			if wErr := server.WriteRPCResponseHTTPError(w, http.StatusInternalServerError, res); wErr != nil {
				logger.Error("failed to write response", "err", wErr)
			}
			return
		}
		args = append(args, fnArgs...)

		returns := rpcFunc.f.Call(args)

		logger.Debug("HTTPRestRPC", "method", r.URL.Path, "args", args, "returns", returns)
		result, err := unreflectResult(returns)
		if err != nil {
			if err := server.WriteRPCResponseHTTPError(w, http.StatusInternalServerError,
				types.RPCInternalError(dummyID, err)); err != nil {
				logger.Error("failed to write response", "err", err)
				return
			}
			return
		}

		resp := types.NewRPCSuccessResponse(dummyID, result)
		if rpcFunc.cacheableWithArgs(args) {
			err = server.WriteCacheableRPCResponseHTTP(w, resp)
		} else {
			err = server.WriteRPCResponseHTTP(w, resp)
		}
		if err != nil {
			logger.Error("failed to write response", "err", err)
			return
		}
	}
}

// NewRPCFunc wraps a function for introspection.
// f is the function, args are comma separated argument names
func NewRPCFunc(f interface{}, args string, options ...Option) *RPCFunc {
	return newRPCFunc(f, args, options...)
}

func newRPCFunc(f interface{}, args string, options ...Option) *RPCFunc {
	var argNames []string
	if args != "" {
		argNames = strings.Split(args, ",")
	}

	r := &RPCFunc{
		f:        reflect.ValueOf(f),
		args:     funcArgTypes(f),
		returns:  funcReturnTypes(f),
		argNames: argNames,
	}

	for _, opt := range options {
		opt(r)
	}

	return r
}

// return a function's argument types
func funcArgTypes(f interface{}) []reflect.Type {
	t := reflect.TypeOf(f)
	n := t.NumIn()
	typez := make([]reflect.Type, n)
	for i := 0; i < n; i++ {
		typez[i] = t.In(i)
	}
	return typez
}

// return a function's return types
func funcReturnTypes(f interface{}) []reflect.Type {
	t := reflect.TypeOf(f)
	n := t.NumOut()
	typez := make([]reflect.Type, n)
	for i := 0; i < n; i++ {
		typez[i] = t.Out(i)
	}
	return typez
}

// cacheableWithArgs returns whether or not a call to this function is cacheable,
// given the specified arguments.
func (f *RPCFunc) cacheableWithArgs(args []reflect.Value) bool {
	if !f.cacheable {
		return false
	}
	// Skip the context variable common to all RPC functions
	for i := 1; i < len(f.args); i++ {
		// f.argNames does not include the context variable
		argName := f.argNames[i-1]
		if _, hasDefault := f.noCacheDefArgs[argName]; hasDefault {
			// Argument with default value was not supplied
			if i >= len(args) {
				return false
			}
			// Argument with default value is set to its zero value
			if args[i].IsZero() {
				return false
			}
		}
	}
	return true
}

// NOTE: assume returns is result struct and error. If error is not nil, return it
func unreflectResult(returns []reflect.Value) (interface{}, error) {
	errV := returns[1]
	if errV.Interface() != nil {
		return nil, fmt.Errorf("%v", errV.Interface())
	}
	rv := returns[0]
	// the result is a registered interface,
	// we need a pointer to it so we can marshal with type byte
	rvp := reflect.New(rv.Type())
	rvp.Elem().Set(rv)
	return rvp.Interface(), nil
}

// Covert an http query to a list of properly typed values.
// To be properly decoded the arg must be a concrete type from CometBFT (if its an interface).
func httpParamsToArgs(rpcFunc *RPCFunc, r *http.Request) ([]reflect.Value, error) {
	// skip types.Context
	const argsOffset = 1

	values := make([]reflect.Value, len(rpcFunc.argNames))

	for i, name := range rpcFunc.argNames {
		argType := rpcFunc.args[i+argsOffset]

		values[i] = reflect.Zero(argType) // set default for that type

		arg := getParam(r, name)
		// log.Notice("param to arg", "argType", argType, "name", name, "arg", arg)

		if arg == "" {
			continue
		}

		v, ok, err := nonJSONStringToArg(argType, arg)
		if err != nil {
			return nil, err
		}
		if ok {
			values[i] = v
			continue
		}

		values[i], err = jsonStringToArg(argType, arg)
		if err != nil {
			return nil, err
		}
	}

	return values, nil
}

func jsonStringToArg(rt reflect.Type, arg string) (reflect.Value, error) {
	rv := reflect.New(rt)
	err := cmtjson.Unmarshal([]byte(arg), rv.Interface())
	if err != nil {
		return rv, err
	}
	rv = rv.Elem()
	return rv, nil
}

func nonJSONStringToArg(rt reflect.Type, arg string) (reflect.Value, bool, error) {
	if rt.Kind() == reflect.Ptr {
		rv1, ok, err := nonJSONStringToArg(rt.Elem(), arg)
		switch {
		case err != nil:
			return reflect.Value{}, false, err
		case ok:
			rv := reflect.New(rt.Elem())
			rv.Elem().Set(rv1)
			return rv, true, nil
		default:
			return reflect.Value{}, false, nil
		}
	} else {
		return _nonJSONStringToArg(rt, arg)
	}
}

// NOTE: rt.Kind() isn't a pointer.
func _nonJSONStringToArg(rt reflect.Type, arg string) (reflect.Value, bool, error) {
	isIntString := reInt.Match([]byte(arg))
	isQuotedString := strings.HasPrefix(arg, `"`) && strings.HasSuffix(arg, `"`)
	isHexString := strings.HasPrefix(strings.ToLower(arg), "0x")

	var expectingString, expectingByteSlice, expectingInt bool
	switch rt.Kind() {
	case reflect.Int,
		reflect.Uint,
		reflect.Int8,
		reflect.Uint8,
		reflect.Int16,
		reflect.Uint16,
		reflect.Int32,
		reflect.Uint32,
		reflect.Int64,
		reflect.Uint64:
		expectingInt = true
	case reflect.String:
		expectingString = true
	case reflect.Slice:
		expectingByteSlice = rt.Elem().Kind() == reflect.Uint8
	}

	if isIntString && expectingInt {
		qarg := `"` + arg + `"`
		rv, err := jsonStringToArg(rt, qarg)
		if err != nil {
			return rv, false, err
		}

		return rv, true, nil
	}

	if isHexString {
		if !expectingString && !expectingByteSlice {
			err := fmt.Errorf("got a hex string arg, but expected '%s'",
				rt.Kind().String())
			return reflect.ValueOf(nil), false, err
		}

		var value []byte
		value, err := hex.DecodeString(arg[2:])
		if err != nil {
			return reflect.ValueOf(nil), false, err
		}
		if rt.Kind() == reflect.String {
			return reflect.ValueOf(string(value)), true, nil
		}
		return reflect.ValueOf(value), true, nil
	}

	if isQuotedString && expectingByteSlice {
		v := reflect.New(reflect.TypeOf(""))
		err := cmtjson.Unmarshal([]byte(arg), v.Interface())
		if err != nil {
			return reflect.ValueOf(nil), false, err
		}
		v = v.Elem()
		return reflect.ValueOf([]byte(v.String())), true, nil
	}

	return reflect.ValueOf(nil), false, nil
}

func getParam(r *http.Request, param string) string {
	s := r.URL.Query().Get(param)
	if s == "" {
		s = r.FormValue(param)
	}
	return s
}

// jsonrpc calls grab the given method's function info and runs reflect.Call
func makeJSONRPCHandler(funcMap map[string]*RPCFunc, logger log.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			res := types.RPCInvalidRequestError(nil,
				fmt.Errorf("error reading request body: %w", err),
			)
			if wErr := server.WriteRPCResponseHTTPError(w, http.StatusBadRequest, res); wErr != nil {
				logger.Error("failed to write response", "err", wErr)
			}
			return
		}

		// if it's an empty request (like from a browser), just display a list of
		// functions
		if len(b) == 0 {
			writeListOfEndpoints(w, r, funcMap)
			return
		}

		// first try to unmarshal the incoming request as an array of RPC requests
		var (
			requests  []types.RPCRequest
			responses []types.RPCResponse
		)
		if err := json.Unmarshal(b, &requests); err != nil {
			// next, try to unmarshal as a single request
			var request types.RPCRequest
			if err := json.Unmarshal(b, &request); err != nil {
				res := types.RPCParseError(fmt.Errorf("error unmarshaling request: %w", err))
				if wErr := server.WriteRPCResponseHTTPError(w, http.StatusInternalServerError, res); wErr != nil {
					logger.Error("failed to write response", "err", wErr)
				}
				return
			}
			requests = []types.RPCRequest{request}
		}

		// Set the default response cache to true unless
		// 1. Any RPC request error.
		// 2. Any RPC request doesn't allow to be cached.
		// 3. Any RPC request has the height argument and the value is 0 (the default).
		cache := true
		for _, request := range requests {
			request := request

			// A Notification is a Request object without an "id" member.
			// The Server MUST NOT reply to a Notification, including those that are within a batch request.
			if request.ID == nil {
				logger.Debug(
					"HTTPJSONRPC received a notification, skipping... (please send a non-empty ID if you want to call a method)",
					"req", request,
				)
				continue
			}
			if len(r.URL.Path) > 1 {
				responses = append(
					responses,
					types.RPCInvalidRequestError(request.ID, fmt.Errorf("path %s is invalid", r.URL.Path)),
				)
				cache = false
				continue
			}
			rpcFunc, ok := funcMap[request.Method]
			if !ok || (rpcFunc.ws) {
				responses = append(responses, types.RPCMethodNotFoundError(request.ID))
				cache = false
				continue
			}
			ctx := &types.Context{JSONReq: &request, HTTPReq: r}
			args := []reflect.Value{reflect.ValueOf(ctx)}
			if len(request.Params) > 0 {
				fnArgs, err := jsonParamsToArgs(rpcFunc, request.Params)
				if err != nil {
					responses = append(
						responses,
						types.RPCInvalidParamsError(request.ID, fmt.Errorf("error converting json params to arguments: %w", err)),
					)
					cache = false
					continue
				}
				args = append(args, fnArgs...)
			}

			if cache && !rpcFunc.cacheableWithArgs(args) {
				cache = false
			}

			returns := rpcFunc.f.Call(args)
			result, err := unreflectResult(returns)
			if err != nil {
				responses = append(responses, types.RPCInternalError(request.ID, err))
				continue
			}
			responses = append(responses, types.NewRPCSuccessResponse(request.ID, result))
		}

		if len(responses) > 0 {
			var wErr error
			if cache {
				wErr = server.WriteCacheableRPCResponseHTTP(w, responses...)
			} else {
				wErr = server.WriteRPCResponseHTTP(w, responses...)
			}
			if wErr != nil {
				logger.Error("failed to write responses", "err", wErr)
			}
		}
	}
}

// writes a list of available rpc endpoints as an html page
func writeListOfEndpoints(w http.ResponseWriter, r *http.Request, funcMap map[string]*RPCFunc) {
	noArgNames := []string{}
	argNames := []string{}
	for name, funcData := range funcMap {
		if len(funcData.args) == 0 {
			noArgNames = append(noArgNames, name)
		} else {
			argNames = append(argNames, name)
		}
	}
	sort.Strings(noArgNames)
	sort.Strings(argNames)
	buf := new(bytes.Buffer)
	buf.WriteString("<html><body>")
	buf.WriteString("<br>Available endpoints:<br>")

	for _, name := range noArgNames {
		link := fmt.Sprintf("//%s/%s", r.Host, name)
		buf.WriteString(fmt.Sprintf("<a href=\"%s\">%s</a></br>", link, link))
	}

	buf.WriteString("<br>Endpoints that require arguments:<br>")
	for _, name := range argNames {
		link := fmt.Sprintf("//%s/%s?", r.Host, name)
		funcData := funcMap[name]
		for i, argName := range funcData.argNames {
			link += argName + "=_"
			if i < len(funcData.argNames)-1 {
				link += "&"
			}
		}
		buf.WriteString(fmt.Sprintf("<a href=\"%s\">%s</a></br>", link, link))
	}
	buf.WriteString("</body></html>")
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(200)
	w.Write(buf.Bytes()) //nolint: errcheck
}

// raw is unparsed json (from json.RawMessage) encoding either a map or an
// array.
//
// Example:
//
//	rpcFunc.args = [rpctypes.Context string]
//	rpcFunc.argNames = ["arg"]
func jsonParamsToArgs(rpcFunc *RPCFunc, raw []byte) ([]reflect.Value, error) {
	const argsOffset = 1

	// TODO: Make more efficient, perhaps by checking the first character for '{' or '['?
	// First, try to get the map.
	var m map[string]json.RawMessage
	err := json.Unmarshal(raw, &m)
	if err == nil {
		return mapParamsToArgs(rpcFunc, m, argsOffset)
	}

	// Otherwise, try an array.
	var a []json.RawMessage
	err = json.Unmarshal(raw, &a)
	if err == nil {
		return arrayParamsToArgs(rpcFunc, a, argsOffset)
	}

	// Otherwise, bad format, we cannot parse
	return nil, fmt.Errorf("unknown type for JSON params: %v. Expected map or array", err)
}

func mapParamsToArgs(
	rpcFunc *RPCFunc,
	params map[string]json.RawMessage,
	argsOffset int,
) ([]reflect.Value, error) {
	values := make([]reflect.Value, len(rpcFunc.argNames))
	for i, argName := range rpcFunc.argNames {
		argType := rpcFunc.args[i+argsOffset]

		if p, ok := params[argName]; ok && p != nil && len(p) > 0 {
			val := reflect.New(argType)
			err := cmtjson.Unmarshal(p, val.Interface())
			if err != nil {
				return nil, err
			}
			values[i] = val.Elem()
		} else { // use default for that type
			values[i] = reflect.Zero(argType)
		}
	}

	return values, nil
}

func arrayParamsToArgs(
	rpcFunc *RPCFunc,
	params []json.RawMessage,
	argsOffset int,
) ([]reflect.Value, error) {
	if len(rpcFunc.argNames) != len(params) {
		return nil, fmt.Errorf("expected %v parameters (%v), got %v (%v)",
			len(rpcFunc.argNames), rpcFunc.argNames, len(params), params)
	}

	values := make([]reflect.Value, len(params))
	for i, p := range params {
		argType := rpcFunc.args[i+argsOffset]
		val := reflect.New(argType)
		err := cmtjson.Unmarshal(p, val.Interface())
		if err != nil {
			return nil, err
		}
		values[i] = val.Elem()
	}
	return values, nil
}

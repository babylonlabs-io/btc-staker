package stakerservice_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/babylonlabs-io/btc-staker/stakerservice"
	"github.com/cometbft/cometbft/libs/log"
	rpctypes "github.com/cometbft/cometbft/rpc/jsonrpc/types"
)

// TestRegisterRPCFuncs verifies that routes are protected by Basic Auth.
func TestRegisterRPCFuncs(t *testing.T) {
	username := "testuser"
	password := "testpass"
	routeHealth := "health"

	mux := http.NewServeMux()

	// Mock function map with a sample handler
	funcMap := map[string]*stakerservice.RPCFunc{
		routeHealth: stakerservice.NewRPCFunc(func(_ *rpctypes.Context) (*stakerservice.ResultHealth, error) {
			return &stakerservice.ResultHealth{}, nil
		}, ""),
	}

	stakerservice.RegisterRPCFuncs(mux, funcMap, log.NewNopLogger(), stakerservice.BasicAuthMiddleware(username, password))

	t.Run("Valid Authenticated Request", func(t *testing.T) {
		req := httptest.NewRequest("GET", fmt.Sprintf("/%s", routeHealth), nil)
		req.SetBasicAuth(username, password)

		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
		}
	})

	t.Run("Invalid Credentials", func(t *testing.T) {
		req := httptest.NewRequest("GET", fmt.Sprintf("/%s", routeHealth), nil)
		req.SetBasicAuth("wronguser", "wrongpass")

		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, rr.Code)
		}
	})

	t.Run("No Credentials", func(t *testing.T) {
		req := httptest.NewRequest("GET", fmt.Sprintf("/%s", routeHealth), nil)

		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, rr.Code)
		}
	})
}

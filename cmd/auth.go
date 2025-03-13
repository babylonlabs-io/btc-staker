package cmd

import (
	"fmt"
	"os"

	service "github.com/babylonlabs-io/btc-staker/stakerservice"
)

func GetEnvBasicAuth() (expUsername, expPwd string, err error) {
	expUsername = os.Getenv(service.EnvRouteAuthUser)
	if len(expUsername) == 0 {
		return "", "", fmt.Errorf("the environment variable %s to authenticate the daemon routes is not set", service.EnvRouteAuthUser)
	}

	expPwd = os.Getenv(service.EnvRouteAuthPwd)
	if len(expPwd) == 0 {
		return "", "", fmt.Errorf("the environment variable %s to authenticate the daemon routes is not set", service.EnvRouteAuthPwd)
	}

	return expUsername, expPwd, nil
}

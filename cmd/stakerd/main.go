package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime/pprof"
	"syscall"

	"github.com/babylonlabs-io/btc-staker/metrics"
	staker "github.com/babylonlabs-io/btc-staker/staker"
	scfg "github.com/babylonlabs-io/btc-staker/stakercfg"
	"github.com/babylonlabs-io/btc-staker/stakerservice"
	service "github.com/babylonlabs-io/btc-staker/stakerservice"
	"github.com/joho/godotenv"

	"github.com/jessevdk/go-flags"
)

func main() {
	// Hook interceptor for os signals.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	cfg, cfgLogger, zapLogger, err := scfg.LoadConfig()

	if err != nil {
		var flagsErr *flags.Error
		if !errors.As(err, &flagsErr) || flagsErr.Type != flags.ErrHelp {
			err = fmt.Errorf("failed to load config: %w", err)
			_, _ = fmt.Fprintln(os.Stderr, err)
			//nolint:gocritic
			os.Exit(1)
		}

		// Help was requested, exit normally.
		os.Exit(0)
	}

	// Enable http profiling server if requested.
	if cfg.Profile != "" {
		go func() {
			profileRedirect := http.RedirectHandler("/debug/pprof",
				http.StatusSeeOther)
			http.Handle("/", profileRedirect)
			cfgLogger.Infof("Pprof listening on %v", cfg.Profile)
			//nolint:gosec
			fmt.Println(http.ListenAndServe(cfg.Profile, nil))
		}()
	}

	// Write cpu profile if requested.
	if cfg.CPUProfile != "" {
		f, err := os.Create(cfg.CPUProfile)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		_ = pprof.StartCPUProfile(f)
		defer f.Close()
		defer pprof.StopCPUProfile()
	}

	dbBackend, err := scfg.GetDBBackend(cfg.DBConfig)

	if err != nil {
		err = fmt.Errorf("failed to load db backend: %w", err)
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	stakerMetrics := metrics.NewStakerMetrics()

	// TODO: consider moving this to stakerservice
	staker, err := staker.NewStakerAppFromConfig(
		cfg,
		cfgLogger,
		zapLogger,
		dbBackend,
		stakerMetrics,
	)

	if err != nil {
		cfgLogger.Errorf("failed to create staker app: %v", err)
		os.Exit(1)
	}

	service := service.NewStakerService(
		cfg,
		staker,
		cfgLogger,
		dbBackend,
	)

	if cfg.MetricsConfig.Enabled {
		addr := fmt.Sprintf("%s:%d", cfg.MetricsConfig.Host, cfg.MetricsConfig.ServerPort)
		metrics.Start(cfgLogger, addr, stakerMetrics.Registry)
	}

	if err := godotenv.Load(); err != nil {
		msg := fmt.Sprintf("Error loading .env file: %s.\nThe enviroment variables %s and %s are used to authenticate the daemon routes", err.Error(), stakerservice.EnvRouteAuthUser, stakerservice.EnvRouteAuthPwd)
		cfgLogger.Info(msg)
	}

	expUsername, expPwd, err := getEnvBasicAuth()
	if err != nil {
		cfgLogger.Errorf("failed to create staker app: %v", err)
		os.Exit(1)
	}

	if err = service.RunUntilShutdown(ctx, expUsername, expPwd); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func getEnvBasicAuth() (expUsername, expPwd string, err error) {
	expUsername = os.Getenv(stakerservice.EnvRouteAuthUser)
	if len(expUsername) == 0 {
		return "", "", fmt.Errorf("the enviroment variable %s to authenticate the daemon routes is not set", stakerservice.EnvRouteAuthUser)
	}

	expPwd = os.Getenv(stakerservice.EnvRouteAuthPwd)
	if len(expPwd) == 0 {
		return "", "", fmt.Errorf("the enviroment variable %s to authenticate the daemon routes is not set", stakerservice.EnvRouteAuthPwd)
	}

	return expUsername, expPwd, nil
}

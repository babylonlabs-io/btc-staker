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

	"github.com/babylonlabs-io/btc-staker/cmd"
	"github.com/babylonlabs-io/btc-staker/metrics"
	scfg "github.com/babylonlabs-io/btc-staker/stakercfg"
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

	s, err := service.NewStakerServiceFromConfig(
		cfg,
		cfgLogger,
		zapLogger,
		dbBackend,
		stakerMetrics,
	)

	if err != nil {
		cfgLogger.Errorf("failed to create staker service: %v", err)
		os.Exit(1)
	}

	if cfg.MetricsConfig.Enabled {
		addr := fmt.Sprintf("%s:%d", cfg.MetricsConfig.Host, cfg.MetricsConfig.ServerPort)
		metrics.Start(cfgLogger, addr, stakerMetrics.Registry)
	}

	if err := godotenv.Load(); err != nil {
		msg := fmt.Sprintf(
			"Error loading .env file: %s.\nThe environment variables %s and %s are used to authenticate the daemon routes",
			err.Error(),
			service.EnvRouteAuthUser,
			service.EnvRouteAuthPwd,
		)
		cfgLogger.Info(msg)
	}

	expUsername, expPwd, err := cmd.GetEnvBasicAuth()
	if err != nil {
		cfgLogger.Errorf("failed to create staker app: %v", err)
		os.Exit(1)
	}

	if err = s.RunUntilShutdown(ctx, expUsername, expPwd); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

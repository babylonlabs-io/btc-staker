// Package types provides common type definitions for the staker daemon.
// nolint: revive
package types

// FeeEstimationMode represents the fee estimation mode.
type FeeEstimationMode int

const (
	// StaticFeeEstimation uses a static fee rate.
	StaticFeeEstimation FeeEstimationMode = iota
	// DynamicFeeEstimation defines dynamic calculation of fee.
	DynamicFeeEstimation
)

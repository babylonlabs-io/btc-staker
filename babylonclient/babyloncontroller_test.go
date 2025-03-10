package babylonclient_test

import (
	"testing"

	"github.com/babylonlabs-io/btc-staker/babylonclient"
	"github.com/stretchr/testify/assert"
)

func TestSortBtcStakingParams(t *testing.T) {
	tests := []struct {
		title    string
		params   []babylonclient.BtcStakingParams
		expected []babylonclient.BtcStakingParams
	}{
		{
			title: "sorts params in ascending btc height order",
			params: []babylonclient.BtcStakingParams{
				{BtcActivationHeight: 100},
				{BtcActivationHeight: 50},
				{BtcActivationHeight: 200},
			},
			expected: []babylonclient.BtcStakingParams{
				{BtcActivationHeight: 50},
				{BtcActivationHeight: 100},
				{BtcActivationHeight: 200},
			},
		},
		{
			title: "params are already sorted",
			params: []babylonclient.BtcStakingParams{
				{BtcActivationHeight: 10},
				{BtcActivationHeight: 20},
				{BtcActivationHeight: 30},
			},
			expected: []babylonclient.BtcStakingParams{
				{BtcActivationHeight: 10},
				{BtcActivationHeight: 20},
				{BtcActivationHeight: 30},
			},
		},
		{
			title:    "handles empty slice",
			params:   []babylonclient.BtcStakingParams{},
			expected: []babylonclient.BtcStakingParams{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.title, func(t *testing.T) {
			t.Parallel()

			babylonclient.SortBtcStakingParams(tt.params)
			assert.Equal(t, tt.expected, tt.params)
		})
	}
}

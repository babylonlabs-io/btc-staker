package pop_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/babylonlabs-io/btc-staker/itest/testutil"
	"github.com/babylonlabs-io/btc-staker/staker"
)

var popsToVerify = []staker.Response{
	{
		BabyAddress:   "bbn1xjz8fs9vkmefdqaxan5kv2d09vmwzru7jhy424",
		BTCAddress:    "bc1qcpty6lpueassw9rhfrvkq6h0ufnhmc2nhgvpcr",
		BTCPublicKey:  "79f71003589158b2579345540b08bbc74974c49dd5e0782e31d0de674540d513",
		BTCSignBaby:   "AkcwRAIgcrI2IdD2JSFVIeQmtRA3wFjjiy+qEvqbX57rn6xvWWECIDis7vHSJeR8X91uMQReG0pPQFFLpeM0ga4BW+Tt2V54ASEDefcQA1iRWLJXk0VUCwi7x0l0xJ3V4HguMdDeZ0VA1RM=",
		BabySignBTC:   "FnYTm9ZbhJZY202R9YBkjGEJqeJ/n5McZBpGH38P2pt0YRcjwOh8XgoeVQTU9So7/RHVHHdKNB09DVmtQJ7xtw==",
		BabyPublicKey: "Asezdqkvh+kLbuD75DirSwi/QFbJjFe2SquiivMaPS65",
	},
}

func TestValidatePoPCmd(t *testing.T) {
	t.Parallel()

	// Create a temporary JSON file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "pop.json")

	// Marshal the test data to JSON
	jsonData, err := json.MarshalIndent(popsToVerify[0], "", "  ")
	require.NoError(t, err)

	// Write JSON to temporary file
	err = os.WriteFile(tmpFile, jsonData, 0644)
	require.NoError(t, err)

	// Test ValidatePopCmd with the JSON file
	app := testutil.TestApp()
	validatePop := []string{
		"stakercli", "pop", "validate", tmpFile,
	}
	err = app.Run(validatePop)
	require.NoError(t, err)
}

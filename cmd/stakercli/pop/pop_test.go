package pop_test

import (
	"testing"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/stretchr/testify/require"

	"github.com/babylonlabs-io/btc-staker/cmd/stakercli/pop"
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

func TestPoPValidate(t *testing.T) {
	t.Parallel()

	for _, p := range popsToVerify {
		err := pop.ValidatePop(p, &chaincfg.MainNetParams, "bbn")
		require.NoError(t, err)
	}
}

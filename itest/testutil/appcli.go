package testutil

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/babylonlabs-io/babylon/testutil/datagen"
	cmdadmin "github.com/babylonlabs-io/btc-staker/cmd/stakercli/admin"
	cmddaemon "github.com/babylonlabs-io/btc-staker/cmd/stakercli/daemon"
	"github.com/babylonlabs-io/btc-staker/cmd/stakercli/pop"
	"github.com/babylonlabs-io/btc-staker/cmd/stakercli/transaction"
	"github.com/babylonlabs-io/networks/parameters/parser"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"
)

var (
	defaultParam = parser.VersionedGlobalParams{
		Version:          0,
		ActivationHeight: 100,
		StakingCap:       3000000,
		CapHeight:        0,
		Tag:              "01020304",
		CovenantPks: []string{
			"03ffeaec52a9b407b355ef6967a7ffc15fd6c3fe07de2844d61550475e7a5233e5",
			"03a5c60c2188e833d39d0fa798ab3f69aa12ed3dd2f3bad659effa252782de3c31",
			"0359d3532148a597a2d05c0395bf5f7176044b1cd312f37701a9b4d0aad70bc5a4",
			"0357349e985e742d5131e1e2b227b5170f6350ac2e2feb72254fcc25b3cee21a18",
			"03c8ccb03c379e452f10c81232b41a1ca8b63d0baf8387e57d302c987e5abb8527",
		},
		CovenantQuorum:    3,
		UnbondingTime:     1000,
		UnbondingFee:      1000,
		MaxStakingAmount:  300000,
		MinStakingAmount:  3000,
		MaxStakingTime:    10000,
		MinStakingTime:    100,
		ConfirmationDepth: 10,
	}

	GlobalParams = parser.GlobalParams{
		Versions: []*parser.VersionedGlobalParams{&defaultParam},
	}

	//nolint:errchkjson
	paramsMarshalled, _ = json.Marshal(GlobalParams)
)

func TestApp() *cli.App {
	app := cli.NewApp()
	app.Name = "stakercli"
	app.Commands = append(app.Commands, cmddaemon.DaemonCommands...)
	app.Commands = append(app.Commands, cmdadmin.AdminCommands...)
	app.Commands = append(app.Commands, transaction.TransactionCommands...)
	app.Commands = append(app.Commands, pop.PopCommands...)
	return app
}

func AppRunCreatePhase1StakingTx(r *rand.Rand, t *testing.T, app *cli.App, arguments []string) transaction.CreatePhase1StakingTxResponse {
	args := []string{"stakercli", "transaction", "create-phase1-staking-transaction"}
	args = append(args, arguments...)
	output := appRunWithOutput(r, t, app, args)

	var data transaction.CreatePhase1StakingTxResponse
	err := json.Unmarshal([]byte(output), &data)
	require.NoError(t, err)

	return data
}

func AppRunCreatePhase1StakingTxWithParams(r *rand.Rand, t *testing.T, app *cli.App, arguments []string) transaction.CreatePhase1StakingTxResponse {
	args := []string{"stakercli", "transaction", "create-phase1-staking-transaction-with-params"}
	args = append(args, arguments...)
	output := appRunWithOutput(r, t, app, args)

	var data transaction.CreatePhase1StakingTxResponse
	err := json.Unmarshal([]byte(output), &data)
	require.NoError(t, err)

	return data
}

func appRunWithOutput(r *rand.Rand, t *testing.T, app *cli.App, arguments []string) string {
	outPut := filepath.Join(t.TempDir(), fmt.Sprintf("%s-out.txt", datagen.GenRandomHexStr(r, 10)))
	outPutFile, err := os.Create(outPut)
	require.NoError(t, err)
	defer outPutFile.Close()

	// set file to stdout to read.
	oldStd := os.Stdout
	os.Stdout = outPutFile

	err = app.Run(arguments)
	require.NoError(t, err)

	// set to old stdout
	os.Stdout = oldStd
	return readFromFile(t, outPutFile)
}

func readFromFile(t *testing.T, f *os.File) string {
	_, err := f.Seek(0, 0)
	require.NoError(t, err)

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(f)
	require.NoError(t, err)
	return buf.String()
}

func CreateTempFileWithParams(t require.TestingT) string {
	return CreateTempFileWithData(t, "tmpParams-*.json", paramsMarshalled)
}

func CreateTempFileWithData(t require.TestingT, pattern string, data []byte) string {
	file, err := os.CreateTemp("", pattern)
	require.NoError(t, err)
	defer file.Close()
	_, err = file.Write(data)
	require.NoError(t, err)
	info, err := file.Stat()
	require.NoError(t, err)
	return filepath.Join(os.TempDir(), info.Name())
}

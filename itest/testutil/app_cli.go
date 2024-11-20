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
	"github.com/babylonlabs-io/btc-staker/cmd/stakercli/transaction"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"
)

func TestApp() *cli.App {
	app := cli.NewApp()
	app.Name = "stakercli"
	app.Commands = append(app.Commands, cmddaemon.DaemonCommands...)
	app.Commands = append(app.Commands, cmdadmin.AdminCommands...)
	app.Commands = append(app.Commands, transaction.TransactionCommands...)
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

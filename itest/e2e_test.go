//go:build e2e
// +build e2e

package e2etest

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/babylonlabs-io/btc-staker/itest/containers"
	"github.com/babylonlabs-io/btc-staker/itest/testutil"

	"github.com/babylonlabs-io/babylon/crypto/bip322"
	btcctypes "github.com/babylonlabs-io/babylon/x/btccheckpoint/types"
	"github.com/cometbft/cometbft/crypto/tmhash"

	staking "github.com/babylonlabs-io/babylon/btcstaking"
	txformat "github.com/babylonlabs-io/babylon/btctxformatter"
	"github.com/babylonlabs-io/babylon/testutil/datagen"
	bbntypes "github.com/babylonlabs-io/babylon/types"
	btcstypes "github.com/babylonlabs-io/babylon/x/btcstaking/types"
	ckpttypes "github.com/babylonlabs-io/babylon/x/checkpointing/types"
	"github.com/babylonlabs-io/btc-staker/babylonclient"
	"github.com/babylonlabs-io/btc-staker/metrics"
	"github.com/babylonlabs-io/btc-staker/proto"
	"github.com/babylonlabs-io/btc-staker/staker"
	"github.com/babylonlabs-io/btc-staker/stakercfg"
	service "github.com/babylonlabs-io/btc-staker/stakerservice"
	dc "github.com/babylonlabs-io/btc-staker/stakerservice/client"
	"github.com/babylonlabs-io/btc-staker/types"
	"github.com/babylonlabs-io/btc-staker/utils"
	"github.com/babylonlabs-io/btc-staker/walletcontroller"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkquerytypes "github.com/cosmos/cosmos-sdk/types/query"
	sttypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/lightningnetwork/lnd/kvdb"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// bitcoin params used for testing
var (
	r = rand.New(rand.NewSource(time.Now().Unix()))

	regtestParams = &chaincfg.RegressionNetParams

	eventuallyWaitTimeOut = 10 * time.Second
	eventuallyPollTime    = 250 * time.Millisecond
)

// keyToAddr maps the passed private to corresponding p2pkh address.
func keyToAddr(key *btcec.PrivateKey, net *chaincfg.Params) (btcutil.Address, error) {
	serializedKey := key.PubKey().SerializeCompressed()
	pubKeyAddr, err := btcutil.NewAddressPubKey(serializedKey, net)
	if err != nil {
		return nil, err
	}
	return pubKeyAddr.AddressPubKeyHash(), nil
}

func defaultStakerConfig(t *testing.T, walletName, passphrase, bitcoindHost string) (*stakercfg.Config, *rpcclient.Client) {
	defaultConfig := stakercfg.DefaultConfig()

	// both wallet and node are bicoind
	defaultConfig.BtcNodeBackendConfig.ActiveWalletBackend = types.BitcoindWalletBackend
	defaultConfig.BtcNodeBackendConfig.ActiveNodeBackend = types.BitcoindNodeBackend
	defaultConfig.ActiveNetParams = *regtestParams

	// Fees configuration
	defaultConfig.BtcNodeBackendConfig.FeeMode = "dynamic"
	defaultConfig.BtcNodeBackendConfig.EstimationMode = types.DynamicFeeEstimation

	bitcoindUser := "user"
	bitcoindPass := "pass"

	// Wallet configuration
	defaultConfig.WalletRPCConfig.Host = bitcoindHost
	defaultConfig.WalletRPCConfig.User = bitcoindUser
	defaultConfig.WalletRPCConfig.Pass = bitcoindPass
	defaultConfig.WalletRPCConfig.DisableTLS = true
	defaultConfig.WalletConfig.WalletPass = passphrase
	defaultConfig.WalletConfig.WalletName = walletName

	// node configuration
	defaultConfig.BtcNodeBackendConfig.Bitcoind.RPCHost = bitcoindHost
	defaultConfig.BtcNodeBackendConfig.Bitcoind.RPCUser = bitcoindUser
	defaultConfig.BtcNodeBackendConfig.Bitcoind.RPCPass = bitcoindPass

	// Use rpc polling, as it is our default mode and it is a bit more troublesome
	// to configure ZMQ from inside the bitcoind docker container
	defaultConfig.BtcNodeBackendConfig.Bitcoind.RPCPolling = true
	defaultConfig.BtcNodeBackendConfig.Bitcoind.BlockPollingInterval = 1 * time.Second
	defaultConfig.BtcNodeBackendConfig.Bitcoind.TxPollingInterval = 1 * time.Second

	defaultConfig.StakerConfig.BabylonStallingInterval = 1 * time.Second
	defaultConfig.StakerConfig.UnbondingTxCheckInterval = 1 * time.Second
	defaultConfig.StakerConfig.CheckActiveInterval = 1 * time.Second

	// TODO: After bumping relayer version sending transactions concurrently fails wih
	// fatal error: concurrent map writes
	// For now diable concurrent sends but this need to be sorted out
	defaultConfig.StakerConfig.MaxConcurrentTransactions = 1

	testRpcClient, err := rpcclient.New(&rpcclient.ConnConfig{
		Host:                 bitcoindHost,
		User:                 bitcoindUser,
		Pass:                 bitcoindPass,
		DisableTLS:           true,
		DisableConnectOnNew:  true,
		DisableAutoReconnect: false,
		// we use post mode as it sure it works with either bitcoind or btcwallet
		// we may need to re-consider it later if we need any notifications
		HTTPPostMode: true,
	}, nil)
	require.NoError(t, err)

	return &defaultConfig, testRpcClient
}

type TestManager struct {
	Config           *stakercfg.Config
	Db               kvdb.Backend
	Sa               *staker.App
	BabylonClient    *babylonclient.BabylonController
	WalletPubKey     *btcec.PublicKey
	MinerAddr        btcutil.Address
	wg               *sync.WaitGroup
	serviceAddress   string
	StakerClient     *dc.StakerServiceJSONRPCClient
	CovenantPrivKeys []*btcec.PrivateKey
	BitcoindHandler  *BitcoindTestHandler
	TestRpcClient    *rpcclient.Client
	manger           *containers.Manager
}

type testStakingData struct {
	StakerKey                       *btcec.PublicKey
	StakerBabylonAddr               sdk.AccAddress
	FinalityProviderBabylonPrivKeys []*secp256k1.PrivKey
	FinalityProviderBabylonAddrs    []sdk.AccAddress
	FinalityProviderBtcPrivKeys     []*btcec.PrivateKey
	FinalityProviderBtcKeys         []*btcec.PublicKey
	StakingTime                     uint16
	StakingAmount                   int64
}

func (d *testStakingData) GetNumRestakedFPs() int {
	return len(d.FinalityProviderBabylonPrivKeys)
}

func (tm *TestManager) getTestStakingData(
	t *testing.T,
	stakerKey *btcec.PublicKey,
	stakingTime uint16,
	stakingAmount int64,
	numRestakedFPs int,
) *testStakingData {
	fpBTCSKs, fpBTCPKs, err := datagen.GenRandomBTCKeyPairs(r, numRestakedFPs)
	require.NoError(t, err)

	fpBBNSKs, fpBBNAddrs := make([]*secp256k1.PrivKey, numRestakedFPs), make([]sdk.AccAddress, numRestakedFPs)
	strAddrs := make([]string, numRestakedFPs)
	for i := 0; i < numRestakedFPs; i++ {
		fpBBNSK := secp256k1.GenPrivKey()
		fpAddr := sdk.AccAddress(fpBBNSK.PubKey().Address().Bytes())

		fpBBNSKs[i] = fpBBNSK
		fpBBNAddrs[i] = fpAddr
		strAddrs[i] = fpAddr.String()
	}

	_, _, err = tm.manger.BabylondTxBankMultiSend(t, "node0", "1000000ubbn", strAddrs...)
	require.NoError(t, err)

	return &testStakingData{
		StakerKey: stakerKey,
		// the staker babylon addr needs to be the same one that is going to sign
		// the transaction in the end
		StakerBabylonAddr:               tm.BabylonClient.GetKeyAddress(),
		FinalityProviderBabylonPrivKeys: fpBBNSKs,
		FinalityProviderBabylonAddrs:    fpBBNAddrs,
		FinalityProviderBtcPrivKeys:     fpBTCSKs,
		FinalityProviderBtcKeys:         fpBTCPKs,
		StakingTime:                     stakingTime,
		StakingAmount:                   stakingAmount,
	}
}

func (td *testStakingData) withStakingTime(time uint16) *testStakingData {
	tdCopy := *td
	tdCopy.StakingTime = time
	return &tdCopy
}

func (td *testStakingData) withStakingAmout(amout int64) *testStakingData {
	tdCopy := *td
	tdCopy.StakingAmount = int64(amout)
	return &tdCopy
}

func StartManager(
	t *testing.T,
	ctx context.Context,
	numMatureOutputsInWallet uint32,
) *TestManager {
	manager, err := containers.NewManager(t)
	require.NoError(t, err)

	bitcoindHandler := NewBitcoindHandler(t, manager)
	bitcoind := bitcoindHandler.Start()
	passphrase := "pass"
	walletName := "test-wallet"
	_ = bitcoindHandler.CreateWallet(walletName, passphrase)
	// only outputs which are 100 deep are mature
	br := bitcoindHandler.GenerateBlocks(int(numMatureOutputsInWallet) + 100)

	minerAddressDecoded, err := btcutil.DecodeAddress(br.Address, regtestParams)
	require.NoError(t, err)

	quorum := 2
	numCovenants := 3
	var coventantPrivKeys []*btcec.PrivateKey
	for i := 0; i < numCovenants; i++ {
		covenantPrivKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		coventantPrivKeys = append(coventantPrivKeys, covenantPrivKey)
	}

	var buff bytes.Buffer
	err = regtestParams.GenesisBlock.Header.Serialize(&buff)
	require.NoError(t, err)
	baseHeaderHex := hex.EncodeToString(buff.Bytes())

	pkScript, err := txscript.PayToAddrScript(minerAddressDecoded)
	require.NoError(t, err)

	tmpDir, err := testutil.TempDir(t)
	require.NoError(t, err)
	babylond, err := manager.RunBabylondResource(
		t,
		tmpDir,
		quorum,
		baseHeaderHex,
		hex.EncodeToString(pkScript), // all slashing will be sent back to wallet
		coventantPrivKeys[0].PubKey(),
		coventantPrivKeys[1].PubKey(),
		coventantPrivKeys[2].PubKey(),
	)
	require.NoError(t, err)

	rpcHost := fmt.Sprintf("127.0.0.1:%s", bitcoind.GetPort("18443/tcp"))
	cfg, c := defaultStakerConfig(t, walletName, passphrase, rpcHost)
	cfg.BtcNodeBackendConfig.Bitcoind.RPCHost = rpcHost
	cfg.WalletRPCConfig.Host = fmt.Sprintf("127.0.0.1:%s", bitcoind.GetPort("18443/tcp"))

	// update port with the dynamically allocated one from docker
	cfg.BabylonConfig.RPCAddr = fmt.Sprintf("http://localhost:%s", babylond.GetPort("26657/tcp"))
	cfg.BabylonConfig.GRPCAddr = fmt.Sprintf("https://localhost:%s", babylond.GetPort("9090/tcp"))

	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	logger.Out = os.Stdout

	// babylon configs for sending transactions
	cfg.BabylonConfig.KeyDirectory = filepath.Join(tmpDir, "node0", "babylond")
	// need to use this one to send otherwise we will have account sequence mismatch
	// errors
	cfg.BabylonConfig.Key = "test-spending-key"

	// Big adjustment to make sure we have enough gas in our transactions
	cfg.BabylonConfig.GasAdjustment = 3.0

	dirPath := filepath.Join(os.TempDir(), "stakerd", "e2etest")
	err = os.MkdirAll(dirPath, 0755)
	require.NoError(t, err)
	dbTempDir, err := os.MkdirTemp(dirPath, "db")
	require.NoError(t, err)
	cfg.DBConfig.DBPath = dbTempDir

	dbbackend, err := stakercfg.GetDBBackend(cfg.DBConfig)
	require.NoError(t, err)

	m := metrics.NewStakerMetrics()
	stakerApp, err := staker.NewStakerAppFromConfig(cfg, logger, zapLogger, dbbackend, m)
	require.NoError(t, err)
	// we require separate client to send BTC headers to babylon node (interface does not need this method?)
	bl, err := babylonclient.NewBabylonController(cfg.BabylonConfig, &cfg.ActiveNetParams, logger, zapLogger)
	require.NoError(t, err)

	walletClient := stakerApp.Wallet()

	err = walletClient.UnlockWallet(20)
	require.NoError(t, err)

	info, err := c.GetAddressInfo(br.Address)
	require.NoError(t, err)

	pubKeyHex := *info.PubKey
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	require.NoError(t, err)
	walletPubKey, err := btcec.ParsePubKey(pubKeyBytes)
	require.NoError(t, err)

	addressString := fmt.Sprintf("127.0.0.1:%d", testutil.AllocateUniquePort(t))
	addrPort := netip.MustParseAddrPort(addressString)
	address := net.TCPAddrFromAddrPort(addrPort)
	cfg.RPCListeners = append(cfg.RPCListeners, address) // todo(lazar): check with konrad who uses this

	stakerService := service.NewStakerService(
		cfg,
		stakerApp,
		logger,
		dbbackend,
	)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := stakerService.RunUntilShutdown(ctx)
		if err != nil {
			t.Fatalf("Error running server: %v", err)
		}
	}()
	// Wait for the server to start
	time.Sleep(3 * time.Second)

	stakerClient, err := dc.NewStakerServiceJSONRPCClient("tcp://" + addressString)
	require.NoError(t, err)

	return &TestManager{
		Config:           cfg,
		Db:               dbbackend,
		Sa:               stakerApp,
		BabylonClient:    bl,
		WalletPubKey:     walletPubKey,
		MinerAddr:        minerAddressDecoded,
		wg:               &wg,
		serviceAddress:   addressString,
		StakerClient:     stakerClient,
		CovenantPrivKeys: coventantPrivKeys,
		BitcoindHandler:  bitcoindHandler,
		TestRpcClient:    c,
		manger:           manager,
	}
}

func (tm *TestManager) Stop(t *testing.T, cancelFunc context.CancelFunc) {
	cancelFunc()
	tm.wg.Wait()
	err := tm.manger.ClearResources()
	require.NoError(t, err)
	err = os.RemoveAll(tm.Config.DBConfig.DBPath)
	require.NoError(t, err)
}

func (tm *TestManager) RestartApp(t *testing.T, newCtx context.Context, cancelFunc context.CancelFunc) {
	// Restart the app with no-op action
	tm.RestartAppWithAction(t, newCtx, cancelFunc, func(t *testing.T) {})
}

// RestartAppWithAction:
// 1. Stop the staker app
// 2. Perform provided action. Warning:this action must not use staker app as
// app is stopped at this point
// 3. Start the staker app
func (tm *TestManager) RestartAppWithAction(t *testing.T, ctx context.Context, cancelFunc context.CancelFunc, action func(t *testing.T)) {
	// First stop the app
	cancelFunc()
	tm.wg.Wait()

	// Perform the action
	action(t)

	// Now reset all components and start again
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	logger.Out = os.Stdout

	dbbackend, err := stakercfg.GetDBBackend(tm.Config.DBConfig)
	require.NoError(t, err)
	m := metrics.NewStakerMetrics()
	stakerApp, err := staker.NewStakerAppFromConfig(tm.Config, logger, zapLogger, dbbackend, m)
	require.NoError(t, err)

	service := service.NewStakerService(
		tm.Config,
		stakerApp,
		logger,
		dbbackend,
	)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := service.RunUntilShutdown(ctx)
		if err != nil {
			t.Fatalf("Error running server: %v", err)
		}
	}()
	// Wait for the server to start
	time.Sleep(3 * time.Second)

	tm.wg = &wg
	tm.Db = dbbackend
	tm.Sa = stakerApp
	stakerClient, err := dc.NewStakerServiceJSONRPCClient("tcp://" + tm.serviceAddress)
	require.NoError(t, err)
	tm.StakerClient = stakerClient
}

func retrieveTransactionFromMempool(t *testing.T, client *rpcclient.Client, hashes []*chainhash.Hash) []*btcutil.Tx {
	var txes []*btcutil.Tx
	for _, txHash := range hashes {
		tx, err := client.GetRawTransaction(txHash)

		if err != nil {
			// this is e2e helper method, so this error most probably some of the
			// transactions are still not in the mempool
			return []*btcutil.Tx{}
		}

		txes = append(txes, tx)
	}
	return txes
}

func GetAllMinedBtcHeadersSinceGenesis(t *testing.T, c *rpcclient.Client) []*wire.BlockHeader {
	height, err := c.GetBlockCount()
	require.NoError(t, err)

	var headers []*wire.BlockHeader

	for i := 1; i <= int(height); i++ {
		hash, err := c.GetBlockHash(int64(i))
		require.NoError(t, err)
		header, err := c.GetBlockHeader(hash)
		require.NoError(t, err)
		headers = append(headers, header)
	}

	return headers
}

func opReturnScript(data []byte) []byte {
	builder := txscript.NewScriptBuilder()
	script, err := builder.AddOp(txscript.OP_RETURN).AddData(data).Script()
	if err != nil {
		panic(err)
	}
	return script
}

func txToBytes(tx *wire.MsgTx) []byte {
	buf := bytes.NewBuffer(make([]byte, 0, tx.SerializeSize()))
	_ = tx.Serialize(buf)
	return buf.Bytes()
}

func txsToBytes(txs []*wire.MsgTx) [][]byte {
	var txsBytes [][]byte
	for _, tx := range txs {
		txsBytes = append(txsBytes, txToBytes(tx))
	}
	return txsBytes
}

func (tm *TestManager) FinalizeUntilEpoch(t *testing.T, epoch uint64) {
	bbnClient := tm.BabylonClient.GetBBNClient()
	ckptParams, err := bbnClient.BTCCheckpointParams()
	require.NoError(t, err)
	// wait until the checkpoint of this epoch is sealed
	require.Eventually(t, func() bool {
		lastSealedCkpt, err := bbnClient.LatestEpochFromStatus(ckpttypes.Sealed)
		if err != nil {
			return false
		}
		return epoch <= lastSealedCkpt.RawCheckpoint.EpochNum
	}, 1*time.Minute, 1*time.Second)

	t.Logf("start finalizing epochs till %d", epoch)
	// Random source for the generation of BTC data
	// r := rand.New(rand.NewSource(time.Now().Unix()))

	// get all checkpoints of these epochs
	pagination := &sdkquerytypes.PageRequest{
		Key:   ckpttypes.CkptsObjectKey(1),
		Limit: epoch,
	}
	resp, err := bbnClient.RawCheckpoints(pagination)
	require.NoError(t, err)
	require.Equal(t, int(epoch), len(resp.RawCheckpoints))

	submitter := tm.BabylonClient.GetKeyAddress()

	for _, checkpoint := range resp.RawCheckpoints {
		// currentBtcTipResp, err := tm.BabylonClient.QueryBtcLightClientTip()
		// require.NoError(t, err)
		// tipHeader, err := bbntypes.NewBTCHeaderBytesFromHex(currentBtcTipResp.HeaderHex)
		// require.NoError(t, err)

		rawCheckpoint, err := checkpoint.Ckpt.ToRawCheckpoint()
		require.NoError(t, err)

		btcCheckpoint, err := ckpttypes.FromRawCkptToBTCCkpt(rawCheckpoint, submitter)
		require.NoError(t, err)

		babylonTagBytes, err := hex.DecodeString("01020304")
		require.NoError(t, err)

		p1, p2, err := txformat.EncodeCheckpointData(
			babylonTagBytes,
			txformat.CurrentVersion,
			btcCheckpoint,
		)

		err = tm.Sa.Wallet().UnlockWallet(60)
		require.NoError(t, err)
		tx1, err := tm.Sa.Wallet().CreateAndSignTx(
			[]*wire.TxOut{
				wire.NewTxOut(0, opReturnScript(p1)),
			},
			2000,
			tm.MinerAddr,
			nil,
		)
		require.NoError(t, err)
		_, err = tm.Sa.Wallet().SendRawTransaction(tx1, true)
		require.NoError(t, err)

		resp1 := tm.BitcoindHandler.GenerateBlocks(1)

		tx2, err := tm.Sa.Wallet().CreateAndSignTx(
			[]*wire.TxOut{
				wire.NewTxOut(0, opReturnScript(p2)),
			},
			2000,
			tm.MinerAddr,
			nil,
		)
		require.NoError(t, err)
		_, err = tm.Sa.Wallet().SendRawTransaction(tx2, true)
		require.NoError(t, err)
		resp2 := tm.BitcoindHandler.GenerateBlocks(1)

		block1Hash, err := chainhash.NewHashFromStr(resp1.Blocks[0])
		require.NoError(t, err)
		block2Hash, err := chainhash.NewHashFromStr(resp2.Blocks[0])
		require.NoError(t, err)

		block1, err := tm.TestRpcClient.GetBlock(block1Hash)
		require.NoError(t, err)
		block2, err := tm.TestRpcClient.GetBlock(block2Hash)
		require.NoError(t, err)

		_, err = tm.BabylonClient.InsertBtcBlockHeaders([]*wire.BlockHeader{
			&block1.Header,
			&block2.Header,
		})

		header1Bytes := bbntypes.NewBTCHeaderBytesFromBlockHeader(&block1.Header)
		header2Bytes := bbntypes.NewBTCHeaderBytesFromBlockHeader(&block2.Header)

		proof1, err := btcctypes.SpvProofFromHeaderAndTransactions(&header1Bytes, txsToBytes(block1.Transactions), 1)
		require.NoError(t, err)
		proof2, err := btcctypes.SpvProofFromHeaderAndTransactions(&header2Bytes, txsToBytes(block2.Transactions), 1)
		require.NoError(t, err)

		_, err = tm.BabylonClient.InsertSpvProofs(submitter.String(), []*btcctypes.BTCSpvProof{
			proof1,
			proof2,
		})
		require.NoError(t, err)

		// 	// wait until this checkpoint is submitted
		require.Eventually(t, func() bool {
			ckpt, err := bbnClient.RawCheckpoint(checkpoint.Ckpt.EpochNum)
			require.NoError(t, err)
			return ckpt.RawCheckpoint.Status == ckpttypes.Submitted
		}, eventuallyWaitTimeOut, eventuallyPollTime)
	}

	tm.mineNEmptyBlocks(t, uint32(ckptParams.Params.CheckpointFinalizationTimeout), true)

	// // wait until the checkpoint of this epoch is finalised
	require.Eventually(t, func() bool {
		lastFinalizedCkpt, err := bbnClient.LatestEpochFromStatus(ckpttypes.Finalized)
		if err != nil {
			t.Logf("failed to get last finalized epoch: %v", err)
			return false
		}
		return epoch <= lastFinalizedCkpt.RawCheckpoint.EpochNum
	}, eventuallyWaitTimeOut, 1*time.Second)

	t.Logf("epoch %d is finalised", epoch)
}

func (tm *TestManager) createAndRegisterFinalityProviders(t *testing.T, testStakingData *testStakingData) {
	params, err := tm.BabylonClient.QueryStakingTracker()
	require.NoError(t, err)

	for i := 0; i < testStakingData.GetNumRestakedFPs(); i++ {
		// ensure the finality provider in testStakingData does not exist yet
		fpResp, err := tm.BabylonClient.QueryFinalityProvider(testStakingData.FinalityProviderBtcKeys[i])
		require.Nil(t, fpResp)
		require.Error(t, err)
		require.True(t, errors.Is(err, babylonclient.ErrFinalityProviderDoesNotExist))

		pop, err := btcstypes.NewPoPBTC(testStakingData.FinalityProviderBabylonAddrs[i], testStakingData.FinalityProviderBtcPrivKeys[i])
		require.NoError(t, err)

		btcFpKey := bbntypes.NewBIP340PubKeyFromBTCPK(testStakingData.FinalityProviderBtcKeys[i])

		// get current finality providers
		resp, err := tm.BabylonClient.QueryFinalityProviders(100, 0)
		require.NoError(t, err)
		// register the generated finality provider
		err = tm.BabylonClient.RegisterFinalityProvider(
			testStakingData.FinalityProviderBabylonAddrs[i],
			testStakingData.FinalityProviderBabylonPrivKeys[i],
			btcFpKey,
			&params.MinComissionRate,
			&sttypes.Description{
				Moniker: "tester",
			},
			pop,
		)
		require.NoError(t, err)

		require.Eventually(t, func() bool {
			resp2, err := tm.BabylonClient.QueryFinalityProviders(100, 0)
			require.NoError(t, err)

			// After registration we should have one finality provider
			return len(resp2.FinalityProviders) == len(resp.FinalityProviders)+1
		}, time.Minute, 250*time.Millisecond)
	}
}

func (tm *TestManager) sendHeadersToBabylon(t *testing.T, headers []*wire.BlockHeader) {
	_, err := tm.BabylonClient.InsertBtcBlockHeaders(headers)
	require.NoError(t, err)
}

func (tm *TestManager) mineNEmptyBlocks(t *testing.T, numHeaders uint32, sendToBabylon bool) []*wire.BlockHeader {
	resp := tm.BitcoindHandler.GenerateBlocks(int(numHeaders))

	var minedHeaders []*wire.BlockHeader
	for _, hash := range resp.Blocks {
		hash, err := chainhash.NewHashFromStr(hash)
		require.NoError(t, err)
		header, err := tm.TestRpcClient.GetBlockHeader(hash)
		require.NoError(t, err)
		minedHeaders = append(minedHeaders, header)
	}

	if sendToBabylon {
		tm.sendHeadersToBabylon(t, minedHeaders)
	}

	return minedHeaders
}

func (tm *TestManager) mineBlock(t *testing.T) *wire.MsgBlock {
	resp := tm.BitcoindHandler.GenerateBlocks(1)
	hash, err := chainhash.NewHashFromStr(resp.Blocks[0])
	require.NoError(t, err)
	header, err := tm.TestRpcClient.GetBlock(hash)
	require.NoError(t, err)
	return header
}

func (tm *TestManager) sendStakingTxBTC(
	t *testing.T,
	testStakingData *testStakingData,
	sendToBabylonFirst bool,
) *chainhash.Hash {
	fpBTCPKs := []string{}
	for i := 0; i < testStakingData.GetNumRestakedFPs(); i++ {
		fpBTCPK := hex.EncodeToString(schnorr.SerializePubKey(testStakingData.FinalityProviderBtcKeys[i]))
		fpBTCPKs = append(fpBTCPKs, fpBTCPK)
	}
	res, err := tm.StakerClient.Stake(
		context.Background(),
		tm.MinerAddr.String(),
		testStakingData.StakingAmount,
		fpBTCPKs,
		int64(testStakingData.StakingTime),
		sendToBabylonFirst,
	)
	require.NoError(t, err)
	txHash := res.TxHash

	stakingDetails, err := tm.StakerClient.StakingDetails(context.Background(), txHash)
	require.NoError(t, err)
	require.Equal(t, stakingDetails.StakingTxHash, txHash)

	if sendToBabylonFirst {
		require.Equal(t, stakingDetails.StakingState, proto.TransactionState_SENT_TO_BABYLON.String())
	} else {
		require.Equal(t, stakingDetails.StakingState, proto.TransactionState_SENT_TO_BTC.String())
	}
	hashFromString, err := chainhash.NewHashFromStr(txHash)
	require.NoError(t, err)

	// only wait for blocks if we are using the old flow, and send staking tx to BTC
	// first
	if !sendToBabylonFirst {
		require.Eventually(t, func() bool {
			txFromMempool := retrieveTransactionFromMempool(t, tm.TestRpcClient, []*chainhash.Hash{hashFromString})
			return len(txFromMempool) == 1
		}, eventuallyWaitTimeOut, eventuallyPollTime)

		mBlock := tm.mineBlock(t)
		require.Equal(t, 2, len(mBlock.Transactions))

		_, err = tm.BabylonClient.InsertBtcBlockHeaders([]*wire.BlockHeader{&mBlock.Header})
		require.NoError(t, err)
	}
	return hashFromString
}

func (tm *TestManager) sendMultipleStakingTx(t *testing.T, testStakingData []*testStakingData, sendToBabylonFirst bool) []*chainhash.Hash {
	var hashes []*chainhash.Hash
	for _, data := range testStakingData {
		fpBTCPKs := []string{}
		for i := 0; i < data.GetNumRestakedFPs(); i++ {
			fpBTCPK := hex.EncodeToString(schnorr.SerializePubKey(data.FinalityProviderBtcKeys[i]))
			fpBTCPKs = append(fpBTCPKs, fpBTCPK)
		}
		res, err := tm.StakerClient.Stake(
			context.Background(),
			tm.MinerAddr.String(),
			data.StakingAmount,
			fpBTCPKs,
			int64(data.StakingTime),
			sendToBabylonFirst,
		)
		require.NoError(t, err)
		txHash, err := chainhash.NewHashFromStr(res.TxHash)
		require.NoError(t, err)
		hashes = append(hashes, txHash)
	}

	for _, txHash := range hashes {
		txHash := txHash
		hashStr := txHash.String()
		stakingDetails, err := tm.StakerClient.StakingDetails(context.Background(), hashStr)
		require.NoError(t, err)
		require.Equal(t, stakingDetails.StakingTxHash, hashStr)

		if sendToBabylonFirst {
			require.Equal(t, stakingDetails.StakingState, proto.TransactionState_SENT_TO_BABYLON.String())
		} else {
			require.Equal(t, stakingDetails.StakingState, proto.TransactionState_SENT_TO_BTC.String())
		}
	}

	if !sendToBabylonFirst {
		mBlock := tm.mineBlock(t)
		require.Equal(t, len(hashes)+1, len(mBlock.Transactions))

		_, err := tm.BabylonClient.InsertBtcBlockHeaders([]*wire.BlockHeader{&mBlock.Header})
		require.NoError(t, err)
	}
	return hashes
}

func (tm *TestManager) sendWatchedStakingTx(
	t *testing.T,
	testStakingData *testStakingData,
	params *babylonclient.StakingParams,
) *chainhash.Hash {
	unbondingTme := params.MinUnbondingTime

	stakingInfo, err := staking.BuildStakingInfo(
		testStakingData.StakerKey,
		testStakingData.FinalityProviderBtcKeys,
		params.CovenantPks,
		params.CovenantQuruomThreshold,
		testStakingData.StakingTime,
		btcutil.Amount(testStakingData.StakingAmount),
		regtestParams,
	)
	require.NoError(t, err)

	err = tm.Sa.Wallet().UnlockWallet(20)
	require.NoError(t, err)

	tx, err := tm.Sa.Wallet().CreateAndSignTx(
		[]*wire.TxOut{stakingInfo.StakingOutput},
		2000,
		tm.MinerAddr,
		nil,
	)
	require.NoError(t, err)
	txHash := tx.TxHash()
	_, err = tm.Sa.Wallet().SendRawTransaction(tx, true)
	require.NoError(t, err)

	// Wait for tx to be in mempool
	require.Eventually(t, func() bool {
		tx, err := tm.TestRpcClient.GetRawTransaction(&txHash)
		if err != nil {
			return false
		}

		if tx == nil {
			return false
		}

		return true
	}, 1*time.Minute, eventuallyPollTime)

	stakingOutputIdx := 0

	require.NoError(t, err)

	slashingTx, err := staking.BuildSlashingTxFromStakingTxStrict(
		tx,
		uint32(stakingOutputIdx),
		params.SlashingPkScript,
		testStakingData.StakerKey,
		unbondingTme,
		int64(params.MinSlashingTxFeeSat)+10,
		params.SlashingRate,
		regtestParams,
	)
	require.NoError(t, err)

	stakingTxSlashingPathInfo, err := stakingInfo.SlashingPathSpendInfo()
	require.NoError(t, err)

	slashingSigResult, err := tm.Sa.Wallet().SignOneInputTaprootSpendingTransaction(
		&walletcontroller.TaprootSigningRequest{
			FundingOutput: stakingInfo.StakingOutput,
			TxToSign:      slashingTx,
			SignerAddress: tm.MinerAddr,
			SpendDescription: &walletcontroller.SpendPathDescription{
				ControlBlock: &stakingTxSlashingPathInfo.ControlBlock,
				ScriptLeaf:   &stakingTxSlashingPathInfo.RevealedLeaf,
			},
		},
	)

	require.NoError(t, err)
	require.NotNil(t, slashingSigResult.Signature)

	serializedStakingTx, err := utils.SerializeBtcTransaction(tx)
	require.NoError(t, err)
	serializedSlashingTx, err := utils.SerializeBtcTransaction(slashingTx)
	require.NoError(t, err)
	// Build unbonding related data
	unbondingFee := params.UnbondingFee
	unbondingAmount := btcutil.Amount(testStakingData.StakingAmount) - unbondingFee

	unbondingInfo, err := staking.BuildUnbondingInfo(
		testStakingData.StakerKey,
		testStakingData.FinalityProviderBtcKeys,
		params.CovenantPks,
		params.CovenantQuruomThreshold,
		unbondingTme,
		unbondingAmount,
		regtestParams,
	)
	require.NoError(t, err)

	unbondingSlashingPathInfo, err := unbondingInfo.SlashingPathSpendInfo()
	require.NoError(t, err)

	unbondingTx := wire.NewMsgTx(2)
	unbondingTx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&txHash, uint32(stakingOutputIdx)), nil, nil))
	unbondingTx.AddTxOut(unbondingInfo.UnbondingOutput)

	slashUnbondingTx, err := staking.BuildSlashingTxFromStakingTxStrict(
		unbondingTx,
		0,
		params.SlashingPkScript,
		testStakingData.StakerKey,
		unbondingTme,
		int64(params.MinSlashingTxFeeSat)+10,
		params.SlashingRate,
		regtestParams,
	)
	require.NoError(t, err)

	slashingUnbondingSigResult, err := tm.Sa.Wallet().SignOneInputTaprootSpendingTransaction(
		&walletcontroller.TaprootSigningRequest{
			FundingOutput: unbondingTx.TxOut[0],
			TxToSign:      slashUnbondingTx,
			SignerAddress: tm.MinerAddr,
			SpendDescription: &walletcontroller.SpendPathDescription{
				ControlBlock: &unbondingSlashingPathInfo.ControlBlock,
				ScriptLeaf:   &unbondingSlashingPathInfo.RevealedLeaf,
			},
		},
	)

	require.NoError(t, err)
	require.NotNil(t, slashingUnbondingSigResult.Signature)

	serializedUnbondingTx, err := utils.SerializeBtcTransaction(unbondingTx)
	require.NoError(t, err)
	serializedSlashUnbondingTx, err := utils.SerializeBtcTransaction(slashUnbondingTx)
	require.NoError(t, err)

	babylonAddrHash := tmhash.Sum(testStakingData.StakerBabylonAddr.Bytes())

	sig, err := tm.Sa.Wallet().SignBip322NativeSegwit(babylonAddrHash, tm.MinerAddr)
	require.NoError(t, err)

	pop, err := babylonclient.NewBabylonBip322Pop(
		babylonAddrHash,
		sig,
		tm.MinerAddr,
	)
	require.NoError(t, err)

	fpBTCPKs := []string{}
	for i := 0; i < testStakingData.GetNumRestakedFPs(); i++ {
		fpBTCPK := hex.EncodeToString(schnorr.SerializePubKey(testStakingData.FinalityProviderBtcKeys[i]))
		fpBTCPKs = append(fpBTCPKs, fpBTCPK)
	}
	_, err = tm.StakerClient.WatchStaking(
		context.Background(),
		hex.EncodeToString(serializedStakingTx),
		int(testStakingData.StakingTime),
		int(testStakingData.StakingAmount),
		hex.EncodeToString(schnorr.SerializePubKey(testStakingData.StakerKey)),
		fpBTCPKs,
		hex.EncodeToString(serializedSlashingTx),
		hex.EncodeToString(slashingSigResult.Signature.Serialize()),
		testStakingData.StakerBabylonAddr.String(),
		tm.MinerAddr.String(),
		hex.EncodeToString(pop.BtcSig),
		hex.EncodeToString(serializedUnbondingTx),
		hex.EncodeToString(serializedSlashUnbondingTx),
		hex.EncodeToString(slashingUnbondingSigResult.Signature.Serialize()),
		int(unbondingTme),
		// Use schnor verification
		int(btcstypes.BTCSigType_BIP322),
	)
	require.NoError(t, err)

	txs := retrieveTransactionFromMempool(t, tm.TestRpcClient, []*chainhash.Hash{&txHash})
	require.Len(t, txs, 1)

	mBlock := tm.mineBlock(t)
	require.Equal(t, 2, len(mBlock.Transactions))
	_, err = tm.BabylonClient.InsertBtcBlockHeaders([]*wire.BlockHeader{&mBlock.Header})
	require.NoError(t, err)

	return &txHash
}

func (tm *TestManager) spendStakingTxWithHash(t *testing.T, stakingTxHash *chainhash.Hash) (*chainhash.Hash, *btcutil.Amount) {
	res, err := tm.StakerClient.SpendStakingTransaction(context.Background(), stakingTxHash.String())
	require.NoError(t, err)
	spendTxHash, err := chainhash.NewHashFromStr(res.TxHash)
	require.NoError(t, err)

	iAmount, err := strconv.ParseInt(res.TxValue, 10, 64)
	require.NoError(t, err)
	spendTxValue := btcutil.Amount(iAmount)

	require.Eventually(t, func() bool {
		txFromMempool := retrieveTransactionFromMempool(t, tm.TestRpcClient, []*chainhash.Hash{spendTxHash})
		return len(txFromMempool) == 1
	}, eventuallyWaitTimeOut, eventuallyPollTime)

	sendTx := retrieveTransactionFromMempool(t, tm.TestRpcClient, []*chainhash.Hash{spendTxHash})[0]

	// Tx is in mempool
	txDetails, txState, err := tm.Sa.Wallet().TxDetails(spendTxHash, sendTx.MsgTx().TxOut[0].PkScript)
	require.NoError(t, err)
	require.Nil(t, txDetails)
	require.Equal(t, txState, walletcontroller.TxInMemPool)

	// Block with spend is mined
	mBlock1 := tm.mineBlock(t)
	require.Equal(t, 2, len(mBlock1.Transactions))

	// Tx is in chain
	txDetails, txState, err = tm.Sa.Wallet().TxDetails(spendTxHash, sendTx.MsgTx().TxOut[0].PkScript)
	require.NoError(t, err)
	require.NotNil(t, txDetails)
	require.Equal(t, txState, walletcontroller.TxInChain)

	return spendTxHash, &spendTxValue
}

func (tm *TestManager) waitForStakingTxState(t *testing.T, txHash *chainhash.Hash, expectedState proto.TransactionState) {
	require.Eventually(t, func() bool {
		detailResult, err := tm.StakerClient.StakingDetails(context.Background(), txHash.String())
		if err != nil {
			return false
		}
		return detailResult.StakingState == expectedState.String()
	}, 1*time.Minute, eventuallyPollTime)
}

func (tm *TestManager) walletUnspentsOutputsContainsOutput(t *testing.T, from btcutil.Address, withValue btcutil.Amount) bool {
	unspentOutputs, err := tm.Sa.ListUnspentOutputs()
	require.NoError(t, err)

	var containsOutput bool = false

	for _, output := range unspentOutputs {
		if output.Address == tm.MinerAddr.String() && int64(output.Amount) == int64(withValue) {
			containsOutput = true
		}
	}

	return containsOutput
}

func (tm *TestManager) insertAllMinedBlocksToBabylon(t *testing.T) {
	headers := GetAllMinedBtcHeadersSinceGenesis(t, tm.TestRpcClient)
	_, err := tm.BabylonClient.InsertBtcBlockHeaders(headers)
	require.NoError(t, err)
}

func (tm *TestManager) insertCovenantSigForDelegation(
	t *testing.T,
	btcDel *btcstypes.BTCDelegationResponse,
) {
	fpBTCPKs, err := bbntypes.NewBTCPKsFromBIP340PKs(btcDel.FpBtcPkList)
	require.NoError(t, err)

	slashingTxBytes, err := hex.DecodeString(btcDel.SlashingTxHex)
	require.NoError(t, err)
	slashingTx := btcstypes.BTCSlashingTx(slashingTxBytes)
	stakingTx := btcDel.StakingTxHex
	stakingMsgTx, _, err := bbntypes.NewBTCTxFromHex(stakingTx)
	require.NoError(t, err)

	cl := tm.Sa.BabylonController()
	params, err := cl.Params()
	require.NoError(t, err)

	stakingInfo, err := staking.BuildStakingInfo(
		btcDel.BtcPk.MustToBTCPK(),
		fpBTCPKs,
		params.CovenantPks,
		params.CovenantQuruomThreshold,
		uint16(btcDel.EndHeight-btcDel.StartHeight),
		btcutil.Amount(btcDel.TotalSat),
		regtestParams,
	)
	slashingPathInfo, err := stakingInfo.SlashingPathSpendInfo()
	require.NoError(t, err)

	covenantSlashingTxSigs, err := datagen.GenCovenantAdaptorSigs(
		tm.CovenantPrivKeys,
		fpBTCPKs,
		stakingMsgTx,
		slashingPathInfo.GetPkScriptPath(),
		&slashingTx,
	)
	require.NoError(t, err)

	// slash unbonding tx spends unbonding tx
	unbondingMsgTx, _, err := bbntypes.NewBTCTxFromHex(btcDel.UndelegationResponse.UnbondingTxHex)
	require.NoError(t, err)
	unbondingInfo, err := staking.BuildUnbondingInfo(
		btcDel.BtcPk.MustToBTCPK(),
		fpBTCPKs,
		params.CovenantPks,
		params.CovenantQuruomThreshold,
		uint16(btcDel.UnbondingTime),
		btcutil.Amount(unbondingMsgTx.TxOut[0].Value),
		regtestParams,
	)
	unbondingSlashingPathInfo, err := unbondingInfo.SlashingPathSpendInfo()
	require.NoError(t, err)

	// generate all covenant signatures from all covenant members
	unbondingSlashingTx, err := btcstypes.NewBTCSlashingTxFromHex(btcDel.UndelegationResponse.SlashingTxHex)
	require.NoError(t, err)
	covenantUnbondingSlashingTxSigs, err := datagen.GenCovenantAdaptorSigs(
		tm.CovenantPrivKeys,
		fpBTCPKs,
		unbondingMsgTx,
		unbondingSlashingPathInfo.GetPkScriptPath(),
		unbondingSlashingTx,
	)
	require.NoError(t, err)

	// each covenant member submits signatures
	unbondingPathInfo, err := stakingInfo.UnbondingPathSpendInfo()
	require.NoError(t, err)
	covUnbondingSigs, err := datagen.GenCovenantUnbondingSigs(
		tm.CovenantPrivKeys,
		stakingMsgTx,
		btcDel.StakingOutputIdx,
		unbondingPathInfo.GetPkScriptPath(),
		unbondingMsgTx,
	)
	require.NoError(t, err)

	var messages []*btcstypes.MsgAddCovenantSigs
	for i := 0; i < len(tm.CovenantPrivKeys); i++ {
		msg := tm.BabylonClient.CreateCovenantMessage(
			bbntypes.NewBIP340PubKeyFromBTCPK(tm.CovenantPrivKeys[i].PubKey()),
			stakingMsgTx.TxHash().String(),
			covenantSlashingTxSigs[i].AdaptorSigs,
			bbntypes.NewBIP340SignatureFromBTCSig(covUnbondingSigs[i]),
			covenantUnbondingSlashingTxSigs[i].AdaptorSigs,
		)
		messages = append(messages, msg)
	}
	// we insert are covenant signatures in on message, this way staker
	// program must handle the case of all signatures being present in Babylon
	// delegation
	// it also speeds up the tests
	_, err = tm.BabylonClient.SubmitMultipleCovenantMessages(messages)
	require.NoError(t, err)
}

func TestStakingFailures(t *testing.T) {
	t.Parallel()
	numMatureOutputs := uint32(200)
	ctx, cancel := context.WithCancel(context.Background())
	tm := StartManager(t, ctx, numMatureOutputs)
	defer tm.Stop(t, cancel)
	tm.insertAllMinedBlocksToBabylon(t)

	cl := tm.Sa.BabylonController()
	params, err := cl.Params()
	require.NoError(t, err)

	testStakingData := tm.getTestStakingData(t, tm.WalletPubKey, params.MinStakingTime, 10000, 1)
	fpKey := hex.EncodeToString(schnorr.SerializePubKey(testStakingData.FinalityProviderBtcKeys[0]))

	tm.createAndRegisterFinalityProviders(t, testStakingData)

	// Duplicated provider key
	_, err = tm.StakerClient.Stake(
		context.Background(),
		tm.MinerAddr.String(),
		testStakingData.StakingAmount,
		[]string{fpKey, fpKey},
		int64(testStakingData.StakingTime),
		false,
	)
	require.Error(t, err)

	// No provider key
	_, err = tm.StakerClient.Stake(
		context.Background(),
		tm.MinerAddr.String(),
		testStakingData.StakingAmount,
		[]string{},
		int64(testStakingData.StakingTime),
		false,
	)
	require.Error(t, err)
}

func TestSendingStakingTransaction(t *testing.T) {
	t.Parallel()
	// need to have at least 300 block on testnet as only then segwit is activated.
	// Mature output is out which has 100 confirmations, which means 200mature outputs
	// will generate 300 blocks
	numMatureOutputs := uint32(200)
	ctx, cancel := context.WithCancel(context.Background())
	tm := StartManager(t, ctx, numMatureOutputs)
	defer tm.Stop(t, cancel)
	tm.insertAllMinedBlocksToBabylon(t)

	cl := tm.Sa.BabylonController()
	params, err := cl.Params()
	require.NoError(t, err)

	testStakingData := tm.getTestStakingData(t, tm.WalletPubKey, params.MinStakingTime, 10000, 1)

	hashed, err := chainhash.NewHash(datagen.GenRandomByteArray(r, 32))
	require.NoError(t, err)
	scr, err := txscript.PayToTaprootScript(tm.CovenantPrivKeys[0].PubKey())
	require.NoError(t, err)
	_, st, erro := tm.Sa.Wallet().TxDetails(hashed, scr)
	// query for exsisting tx is not an error, proper state should be returned
	require.NoError(t, erro)
	require.Equal(t, st, walletcontroller.TxNotFound)

	tm.createAndRegisterFinalityProviders(t, testStakingData)

	txHash := tm.sendStakingTxBTC(t, testStakingData, false)

	go tm.mineNEmptyBlocks(t, params.ConfirmationTimeBlocks, true)
	tm.waitForStakingTxState(t, txHash, proto.TransactionState_SENT_TO_BABYLON)

	pend, err := tm.BabylonClient.QueryPendingBTCDelegations()
	require.NoError(t, err)
	require.Len(t, pend, 1)
	// need to activate delegation to unbond
	tm.insertCovenantSigForDelegation(t, pend[0])
	tm.waitForStakingTxState(t, txHash, proto.TransactionState_DELEGATION_ACTIVE)

	// mine one block less than the amount needed to spend staking tx
	blockForStakingToExpire := uint32(testStakingData.StakingTime) - params.ConfirmationTimeBlocks - 2
	tm.mineNEmptyBlocks(t, blockForStakingToExpire, false)

	withdrawableTransactionsResp, err := tm.StakerClient.WithdrawableTransactions(context.Background(), nil, nil)
	require.NoError(t, err)
	require.Len(t, withdrawableTransactionsResp.Transactions, 0)
	require.Equal(t, withdrawableTransactionsResp.TotalTransactionCount, "1")
	require.Equal(t, withdrawableTransactionsResp.LastWithdrawableTransactionIndex, "0")

	tm.mineNEmptyBlocks(t, 1, false)

	// need to use eventually as we need to wait for information to flow from node to staker program
	require.Eventually(t, func() bool {
		withdrawableTransactionsResp, err = tm.StakerClient.WithdrawableTransactions(context.Background(), nil, nil)
		require.NoError(t, err)
		return len(withdrawableTransactionsResp.Transactions) > 0
	}, eventuallyWaitTimeOut, eventuallyPollTime)

	_, spendTxValue := tm.spendStakingTxWithHash(t, txHash)

	go tm.mineNEmptyBlocks(t, params.ConfirmationTimeBlocks, false)

	tm.waitForStakingTxState(t, txHash, proto.TransactionState_SPENT_ON_BTC)

	require.True(t, tm.walletUnspentsOutputsContainsOutput(t, tm.MinerAddr, *spendTxValue))

	offset := 0
	limit := 10
	transactionsResult, err := tm.StakerClient.ListStakingTransactions(context.Background(), &offset, &limit)
	require.NoError(t, err)
	require.Len(t, transactionsResult.Transactions, 1)
	require.Equal(t, transactionsResult.TotalTransactionCount, "1")
	require.Equal(t, transactionsResult.Transactions[0].StakingTxHash, txHash.String())
}

func TestSendingStakingTransactionWithPreApproval(t *testing.T) {
	t.Parallel()
	// need to have at least 300 block on testnet as only then segwit is activated.
	// Mature output is out which has 100 confirmations, which means 200mature outputs
	// will generate 300 blocks
	numMatureOutputs := uint32(200)
	ctx, cancel := context.WithCancel(context.Background())
	tm := StartManager(t, ctx, numMatureOutputs)
	defer tm.Stop(t, cancel)
	tm.insertAllMinedBlocksToBabylon(t)

	cl := tm.Sa.BabylonController()
	params, err := cl.Params()
	require.NoError(t, err)

	testStakingData := tm.getTestStakingData(t, tm.WalletPubKey, params.MinStakingTime, 10000, 1)

	hashed, err := chainhash.NewHash(datagen.GenRandomByteArray(r, 32))
	require.NoError(t, err)
	scr, err := txscript.PayToTaprootScript(tm.CovenantPrivKeys[0].PubKey())
	require.NoError(t, err)
	_, st, erro := tm.Sa.Wallet().TxDetails(hashed, scr)
	// query for exsisting tx is not an error, proper state should be returned
	require.NoError(t, erro)
	require.Equal(t, st, walletcontroller.TxNotFound)

	tm.createAndRegisterFinalityProviders(t, testStakingData)

	txHash := tm.sendStakingTxBTC(t, testStakingData, true)

	go tm.mineNEmptyBlocks(t, params.ConfirmationTimeBlocks, true)
	tm.waitForStakingTxState(t, txHash, proto.TransactionState_SENT_TO_BABYLON)

	pend, err := tm.BabylonClient.QueryPendingBTCDelegations()
	require.NoError(t, err)
	require.Len(t, pend, 1)
	// need to activate delegation to unbond
	tm.insertCovenantSigForDelegation(t, pend[0])
	tm.waitForStakingTxState(t, txHash, proto.TransactionState_VERIFIED)

	require.Eventually(t, func() bool {
		txFromMempool := retrieveTransactionFromMempool(t, tm.TestRpcClient, []*chainhash.Hash{txHash})
		return len(txFromMempool) == 1
	}, eventuallyWaitTimeOut, eventuallyPollTime)

	mBlock := tm.mineBlock(t)
	require.Equal(t, 2, len(mBlock.Transactions))

	headerBytes := bbntypes.NewBTCHeaderBytesFromBlockHeader(&mBlock.Header)
	proof, err := btcctypes.SpvProofFromHeaderAndTransactions(&headerBytes, txsToBytes(mBlock.Transactions), 1)
	require.NoError(t, err)

	_, err = tm.BabylonClient.InsertBtcBlockHeaders([]*wire.BlockHeader{&mBlock.Header})
	require.NoError(t, err)

	tm.mineNEmptyBlocks(t, params.ConfirmationTimeBlocks, true)

	_, err = tm.BabylonClient.ActivateDelegation(
		*txHash,
		proof,
	)
	require.NoError(t, err)
	tm.waitForStakingTxState(t, txHash, proto.TransactionState_DELEGATION_ACTIVE)

	// check that there is not error when qury for withdrawable transactions
	withdrawableTransactionsResp, err := tm.StakerClient.WithdrawableTransactions(context.Background(), nil, nil)
	require.NoError(t, err)
	require.Len(t, withdrawableTransactionsResp.Transactions, 0)

	//  Unbond pre-approval stake
	resp, err := tm.StakerClient.UnbondStaking(context.Background(), txHash.String())
	require.NoError(t, err)

	unbondingTxHash, err := chainhash.NewHashFromStr(resp.UnbondingTxHash)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		tx, err := tm.TestRpcClient.GetRawTransaction(unbondingTxHash)
		if err != nil {
			return false
		}

		if tx == nil {
			return false

		}
		return true
	}, 1*time.Minute, eventuallyPollTime)

	block := tm.mineBlock(t)
	require.Equal(t, 2, len(block.Transactions))
	require.Equal(t, block.Transactions[1].TxHash(), *unbondingTxHash)
	go tm.mineNEmptyBlocks(t, staker.UnbondingTxConfirmations, false)
	tm.waitForStakingTxState(t, txHash, proto.TransactionState_UNBONDING_CONFIRMED_ON_BTC)

	// Spend unbonding tx of pre-approval stake
	withdrawableTransactionsResp, err = tm.StakerClient.WithdrawableTransactions(context.Background(), nil, nil)
	require.NoError(t, err)
	require.Len(t, withdrawableTransactionsResp.Transactions, 1)

	// We can spend unbonding tx immediately as in e2e test, min unbonding time is 5 blocks and we locked it
	// for 5 blocks, but to consider unbonding tx as confirmed we need to wait for 6 blocks
	// so at this point time lock should already have passed
	tm.spendStakingTxWithHash(t, txHash)
	go tm.mineNEmptyBlocks(t, staker.SpendStakeTxConfirmations, false)
	tm.waitForStakingTxState(t, txHash, proto.TransactionState_SPENT_ON_BTC)
}

func TestMultipleWithdrawableStakingTransactions(t *testing.T) {
	t.Parallel()
	// need to have at least 300 block on testnet as only then segwit is activated.
	// Mature output is out which has 100 confirmations, which means 200mature outputs
	// will generate 300 blocks
	numMatureOutputs := uint32(200)
	ctx, cancel := context.WithCancel(context.Background())
	tm := StartManager(t, ctx, numMatureOutputs)
	defer tm.Stop(t, cancel)
	tm.insertAllMinedBlocksToBabylon(t)

	cl := tm.Sa.BabylonController()
	params, err := cl.Params()
	require.NoError(t, err)
	minStakingTime := params.MinStakingTime
	stakingTime1 := minStakingTime
	stakingTime2 := minStakingTime + 4
	stakingTime3 := minStakingTime + 1
	stakingTime4 := minStakingTime + 2
	stakingTime5 := minStakingTime + 3

	testStakingData1 := tm.getTestStakingData(t, tm.WalletPubKey, stakingTime1, 10000, 1)
	testStakingData2 := testStakingData1.withStakingTime(stakingTime2)
	testStakingData3 := testStakingData1.withStakingTime(stakingTime3)
	testStakingData4 := testStakingData1.withStakingTime(stakingTime4)
	testStakingData5 := testStakingData1.withStakingTime(stakingTime5)

	tm.createAndRegisterFinalityProviders(t, testStakingData1)
	txHashes := tm.sendMultipleStakingTx(t, []*testStakingData{
		testStakingData1,
		testStakingData2,
		testStakingData3,
		testStakingData4,
		testStakingData5,
	}, false)

	go tm.mineNEmptyBlocks(t, params.ConfirmationTimeBlocks, true)

	for _, txHash := range txHashes {
		txHash := txHash
		tm.waitForStakingTxState(t, txHash, proto.TransactionState_SENT_TO_BABYLON)
	}

	// mine enough block so that:
	// stakingTime1, stakingTime3, stakingTime4 are spendable
	blockForStakingToExpire := uint32(testStakingData4.StakingTime) - params.ConfirmationTimeBlocks - 1
	tm.mineNEmptyBlocks(t, blockForStakingToExpire, false)

	require.Eventually(t, func() bool {
		withdrawableTransactionsResp, err := tm.StakerClient.WithdrawableTransactions(context.Background(), nil, nil)
		require.NoError(t, err)
		return len(withdrawableTransactionsResp.Transactions) == 3
	}, eventuallyWaitTimeOut, eventuallyPollTime)

	withdrawableTransactionsResp, err := tm.StakerClient.WithdrawableTransactions(context.Background(), nil, nil)
	require.NoError(t, err)
	require.Len(t, withdrawableTransactionsResp.Transactions, 3)
	require.Equal(t, withdrawableTransactionsResp.LastWithdrawableTransactionIndex, "4")
	// there are total 5 tranascations in database
	require.Equal(t, withdrawableTransactionsResp.TotalTransactionCount, "5")
	// hashes of stakingTime1, stakingTime3, stakingTime4 are spendable
	require.Equal(t, withdrawableTransactionsResp.Transactions[0].StakingTxHash, txHashes[0].String())
	require.Equal(t, withdrawableTransactionsResp.Transactions[1].StakingTxHash, txHashes[2].String())
	require.Equal(t, withdrawableTransactionsResp.Transactions[2].StakingTxHash, txHashes[3].String())

	require.Equal(t, withdrawableTransactionsResp.Transactions[2].TransactionIdx, "4")
}

func TestMultiplePreApprovalTransactions(t *testing.T) {
	t.Parallel()
	// need to have at least 300 block on testnet as only then segwit is activated.
	// Mature output is out which has 100 confirmations, which means 200mature outputs
	// will generate 300 blocks
	numMatureOutputs := uint32(200)
	ctx, cancel := context.WithCancel(context.Background())
	tm := StartManager(t, ctx, numMatureOutputs)
	defer tm.Stop(t, cancel)
	tm.insertAllMinedBlocksToBabylon(t)

	cl := tm.Sa.BabylonController()
	params, err := cl.Params()
	require.NoError(t, err)
	minStakingTime := params.MinStakingTime
	stakingTime1 := minStakingTime
	stakingTime2 := minStakingTime + 4
	stakingTime3 := minStakingTime + 1

	testStakingData1 := tm.getTestStakingData(t, tm.WalletPubKey, stakingTime1, 10000, 1)
	testStakingData2 := testStakingData1.withStakingTime(stakingTime2)
	testStakingData3 := testStakingData1.withStakingTime(stakingTime3)

	tm.createAndRegisterFinalityProviders(t, testStakingData1)
	txHashes := tm.sendMultipleStakingTx(t, []*testStakingData{
		testStakingData1,
		testStakingData2,
		testStakingData3,
	}, true)

	for _, txHash := range txHashes {
		txHash := txHash
		tm.waitForStakingTxState(t, txHash, proto.TransactionState_SENT_TO_BABYLON)
	}

	pend, err := tm.BabylonClient.QueryPendingBTCDelegations()
	require.NoError(t, err)
	require.Len(t, pend, 3)
	tm.insertCovenantSigForDelegation(t, pend[0])
	tm.insertCovenantSigForDelegation(t, pend[1])
	tm.insertCovenantSigForDelegation(t, pend[2])

	for _, txHash := range txHashes {
		txHash := txHash
		tm.waitForStakingTxState(t, txHash, proto.TransactionState_VERIFIED)
	}

	// Ultimately we will get 3 tx in the mempool meaning all staking transactions
	// use valid inputs
	require.Eventually(t, func() bool {
		txFromMempool := retrieveTransactionFromMempool(t, tm.TestRpcClient, txHashes)
		return len(txFromMempool) == 3
	}, eventuallyWaitTimeOut, eventuallyPollTime)
}

func TestSendingWatchedStakingTransaction(t *testing.T) {
	t.Parallel()
	// need to have at least 300 block on testnet as only then segwit is activated.
	// Mature output is out which has 100 confirmations, which means 200mature outputs
	// will generate 300 blocks
	numMatureOutputs := uint32(200)
	ctx, cancel := context.WithCancel(context.Background())
	tm := StartManager(t, ctx, numMatureOutputs)
	defer tm.Stop(t, cancel)
	tm.insertAllMinedBlocksToBabylon(t)

	cl := tm.Sa.BabylonController()
	params, err := cl.Params()
	require.NoError(t, err)

	testStakingData := tm.getTestStakingData(t, tm.WalletPubKey, params.MinStakingTime, 10000, 1)

	tm.createAndRegisterFinalityProviders(t, testStakingData)

	txHash := tm.sendWatchedStakingTx(t, testStakingData, params)
	go tm.mineNEmptyBlocks(t, params.ConfirmationTimeBlocks, true)
	tm.waitForStakingTxState(t, txHash, proto.TransactionState_SENT_TO_BABYLON)
}

func TestRestartingTxNotDeepEnough(t *testing.T) {
	t.Parallel()
	// need to have at least 300 block on testnet as only then segwit is activated.
	// Mature output is out which has 100 confirmations, which means 200mature outputs
	// will generate 300 blocks
	numMatureOutputs := uint32(200)
	ctx, cancel := context.WithCancel(context.Background())
	tm := StartManager(t, ctx, numMatureOutputs)
	defer tm.Stop(t, cancel)
	tm.insertAllMinedBlocksToBabylon(t)

	cl := tm.Sa.BabylonController()
	params, err := cl.Params()
	require.NoError(t, err)

	testStakingData := tm.getTestStakingData(t, tm.WalletPubKey, params.MinStakingTime, 10000, 1)

	tm.createAndRegisterFinalityProviders(t, testStakingData)
	txHash := tm.sendStakingTxBTC(t, testStakingData, false)

	newCtx, newCancel := context.WithCancel(context.Background())
	defer newCancel()
	// restart app when tx is not deep enough
	tm.RestartApp(t, newCtx, cancel)

	go tm.mineNEmptyBlocks(t, params.ConfirmationTimeBlocks, true)
	tm.waitForStakingTxState(t, txHash, proto.TransactionState_SENT_TO_BABYLON)
}

func TestRestartingTxNotOnBabylon(t *testing.T) {
	t.Parallel()
	// need to have at least 300 block on testnet as only then segwit is activated.
	// Mature output is out which has 100 confirmations, which means 200mature outputs
	// will generate 300 blocks
	numMatureOutputs := uint32(200)
	ctx, cancel := context.WithCancel(context.Background())
	tm := StartManager(t, ctx, numMatureOutputs)
	defer tm.Stop(t, cancel)
	tm.insertAllMinedBlocksToBabylon(t)

	cl := tm.Sa.BabylonController()
	params, err := cl.Params()
	require.NoError(t, err)

	testStakingData1 := tm.getTestStakingData(t, tm.WalletPubKey, params.MinStakingTime, 10000, 1)
	testStakingData2 := testStakingData1.withStakingAmout(11000)

	tm.createAndRegisterFinalityProviders(t, testStakingData1)

	txHashes := tm.sendMultipleStakingTx(t, []*testStakingData{
		testStakingData1,
		testStakingData2,
	}, false)

	// Confirm tx on btc
	minedBlocks := tm.mineNEmptyBlocks(t, params.ConfirmationTimeBlocks, false)

	for _, txHash := range txHashes {
		tm.waitForStakingTxState(t, txHash, proto.TransactionState_CONFIRMED_ON_BTC)
	}

	newCtx, newCancel := context.WithCancel(context.Background())
	defer newCancel()
	// restart app, tx is confirmed but not delivered to babylon
	tm.RestartApp(t, newCtx, cancel)

	// send headers to babylon, so that we can send delegation tx
	go tm.sendHeadersToBabylon(t, minedBlocks)

	for _, txHash := range txHashes {
		tm.waitForStakingTxState(t, txHash, proto.TransactionState_SENT_TO_BABYLON)
	}
}

func TestStakingUnbonding(t *testing.T) {
	t.Parallel()
	// need to have at least 300 block on testnet as only then segwit is activated.
	// Mature output is out which has 100 confirmations, which means 200mature outputs
	// will generate 300 blocks
	numMatureOutputs := uint32(200)
	ctx, cancel := context.WithCancel(context.Background())
	tm := StartManager(t, ctx, numMatureOutputs)
	defer tm.Stop(t, cancel)
	tm.insertAllMinedBlocksToBabylon(t)

	cl := tm.Sa.BabylonController()
	params, err := cl.Params()
	require.NoError(t, err)
	// large staking time
	stakingTime := uint16(1000)
	testStakingData := tm.getTestStakingData(t, tm.WalletPubKey, stakingTime, 50000, 1)

	tm.createAndRegisterFinalityProviders(t, testStakingData)

	txHash := tm.sendStakingTxBTC(t, testStakingData, false)

	go tm.mineNEmptyBlocks(t, params.ConfirmationTimeBlocks, true)
	tm.waitForStakingTxState(t, txHash, proto.TransactionState_SENT_TO_BABYLON)
	require.NoError(t, err)

	pend, err := tm.BabylonClient.QueryPendingBTCDelegations()
	require.NoError(t, err)
	require.Len(t, pend, 1)
	// need to activate delegation to unbond
	tm.insertCovenantSigForDelegation(t, pend[0])

	tm.waitForStakingTxState(t, txHash, proto.TransactionState_DELEGATION_ACTIVE)

	resp, err := tm.StakerClient.UnbondStaking(context.Background(), txHash.String())
	require.NoError(t, err)

	unbondingTxHash, err := chainhash.NewHashFromStr(resp.UnbondingTxHash)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		tx, err := tm.TestRpcClient.GetRawTransaction(unbondingTxHash)
		if err != nil {
			return false
		}

		if tx == nil {
			return false

		}

		return true
	}, 1*time.Minute, eventuallyPollTime)

	block := tm.mineBlock(t)
	require.Equal(t, 2, len(block.Transactions))
	require.Equal(t, block.Transactions[1].TxHash(), *unbondingTxHash)
	go tm.mineNEmptyBlocks(t, staker.UnbondingTxConfirmations, false)
	tm.waitForStakingTxState(t, txHash, proto.TransactionState_UNBONDING_CONFIRMED_ON_BTC)

	withdrawableTransactionsResp, err := tm.StakerClient.WithdrawableTransactions(context.Background(), nil, nil)
	require.NoError(t, err)
	require.Len(t, withdrawableTransactionsResp.Transactions, 1)

	// We can spend unbonding tx immediately as in e2e test, min unbonding time is 5 blocks and we locked it
	// for 5 blocks, but to consider unbonding tx as confirmed we need to wait for 6 blocks
	// so at this point time lock should already have passed
	tm.spendStakingTxWithHash(t, txHash)
	go tm.mineNEmptyBlocks(t, staker.SpendStakeTxConfirmations, false)
	tm.waitForStakingTxState(t, txHash, proto.TransactionState_SPENT_ON_BTC)
}

func TestUnbondingRestartWaitingForSignatures(t *testing.T) {
	t.Parallel()
	// need to have at least 300 block on testnet as only then segwit is activated.
	// Mature output is out which has 100 confirmations, which means 200mature outputs
	// will generate 300 blocks
	numMatureOutputs := uint32(200)
	ctx, cancel := context.WithCancel(context.Background())
	tm := StartManager(t, ctx, numMatureOutputs)
	defer tm.Stop(t, cancel)
	tm.insertAllMinedBlocksToBabylon(t)

	cl := tm.Sa.BabylonController()
	params, err := cl.Params()
	require.NoError(t, err)
	// large staking time
	stakingTime := uint16(1000)
	testStakingData := tm.getTestStakingData(t, tm.WalletPubKey, stakingTime, 50000, 1)

	tm.createAndRegisterFinalityProviders(t, testStakingData)

	txHash := tm.sendStakingTxBTC(t, testStakingData, false)

	go tm.mineNEmptyBlocks(t, params.ConfirmationTimeBlocks, true)
	tm.waitForStakingTxState(t, txHash, proto.TransactionState_SENT_TO_BABYLON)
	require.NoError(t, err)

	newCtx, newCancel := context.WithCancel(context.Background())
	defer newCancel()
	// restart app, tx was sent to babylon but we did not receive covenant signatures yet
	tm.RestartApp(t, newCtx, cancel)

	pend, err := tm.BabylonClient.QueryPendingBTCDelegations()
	require.NoError(t, err)
	require.Len(t, pend, 1)
	// need to activate delegation to unbond
	tm.insertCovenantSigForDelegation(t, pend[0])

	tm.waitForStakingTxState(t, txHash, proto.TransactionState_DELEGATION_ACTIVE)

	unbondResponse, err := tm.StakerClient.UnbondStaking(context.Background(), txHash.String())
	require.NoError(t, err)
	unbondingTxHash, err := chainhash.NewHashFromStr(unbondResponse.UnbondingTxHash)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		tx, err := tm.TestRpcClient.GetRawTransaction(unbondingTxHash)
		if err != nil {
			return false
		}

		if tx == nil {
			return false

		}

		return true
	}, 1*time.Minute, eventuallyPollTime)

	block := tm.mineBlock(t)
	require.Equal(t, 2, len(block.Transactions))
	require.Equal(t, block.Transactions[1].TxHash(), *unbondingTxHash)

	go tm.mineNEmptyBlocks(t, staker.UnbondingTxConfirmations, false)
	tm.waitForStakingTxState(t, txHash, proto.TransactionState_UNBONDING_CONFIRMED_ON_BTC)
}

func containsOutput(outputs []walletcontroller.Utxo, address string, amount btcutil.Amount) bool {
	for _, o := range outputs {
		if o.Address == address && o.Amount == amount {
			return true
		}
	}
	return false
}

func TestBitcoindWalletRpcApi(t *testing.T) {
	t.Parallel()
	manager, err := containers.NewManager(t)
	require.NoError(t, err)
	h := NewBitcoindHandler(t, manager)
	bitcoind := h.Start()
	passphrase := "pass"
	numMatureOutputs := 1
	walletName := "test-wallet"
	_ = h.CreateWallet(walletName, passphrase)
	// only outputs which are 100 deep are mature
	_ = h.GenerateBlocks(numMatureOutputs + 100)

	// hardcoded config
	scfg := stakercfg.DefaultConfig()
	scfg.WalletRPCConfig.Host = fmt.Sprintf("127.0.0.1:%s", bitcoind.GetPort("18443/tcp"))
	scfg.WalletRPCConfig.User = "user"
	scfg.WalletRPCConfig.Pass = "pass"
	scfg.ActiveNetParams.Name = "regtest"
	scfg.WalletConfig.WalletPass = passphrase
	scfg.WalletConfig.WalletName = walletName
	scfg.BtcNodeBackendConfig.ActiveWalletBackend = types.BitcoindWalletBackend
	scfg.ActiveNetParams = chaincfg.RegressionNetParams

	// Create wallet controller the same way as in staker program
	wc, err := walletcontroller.NewRPCWalletController(&scfg)
	require.NoError(t, err)

	outputs, err := wc.ListOutputs(true)
	require.NoError(t, err)
	require.Len(t, outputs, numMatureOutputs)

	// easiest way to get address controlled by wallet is to retrive address from one
	// of the outputs
	output := outputs[0]
	walletAddress, err := btcutil.DecodeAddress(output.Address, &scfg.ActiveNetParams)
	require.NoError(t, err)
	payScript, err := txscript.PayToAddrScript(walletAddress)
	require.NoError(t, err)

	// split this output into two: 49 and 1 BTC
	toSend, err := btcutil.NewAmount(1)
	require.NoError(t, err)
	newOutput := wire.NewTxOut(int64(toSend), payScript)
	err = wc.UnlockWallet(20)
	require.NoError(t, err)

	// create transaction which shouls split one of the wallet outputs into two
	tx, err := wc.CreateAndSignTx(
		[]*wire.TxOut{newOutput},
		btcutil.Amount(2000),
		walletAddress,
		nil,
	)
	require.NoError(t, err)

	// send transaction to bitcoin node, it should be accepted
	txHash, err := wc.SendRawTransaction(
		tx,
		false,
	)
	require.NoError(t, err)

	// generates enough blocks to make tx mature
	h.GenerateBlocks(10)
	outputs, err = wc.ListOutputs(true)
	require.NoError(t, err)

	// check that our wallet contains new output which should have 1 BTC
	require.True(t, containsOutput(outputs, walletAddress.EncodeAddress(), toSend), "Not found expected output")

	// check that tx is registered on node side. It requires maintaining txindex
	_, status, err := wc.TxDetails(txHash, payScript)
	require.NoError(t, err)
	require.Equal(t, walletcontroller.TxInChain, status)
}

func TestBitcoindWalletBip322Signing(t *testing.T) {
	t.Parallel()
	manager, err := containers.NewManager(t)
	require.NoError(t, err)
	h := NewBitcoindHandler(t, manager)
	bitcoind := h.Start()
	passphrase := "pass"
	walletName := "test-wallet"
	_ = h.CreateWallet(walletName, passphrase)

	rpcHost := fmt.Sprintf("127.0.0.1:%s", bitcoind.GetPort("18443/tcp"))
	cfg, c := defaultStakerConfig(t, walletName, passphrase, rpcHost)

	segwitAddress, err := c.GetNewAddress("")
	require.NoError(t, err)

	controller, err := walletcontroller.NewRPCWalletController(cfg)
	require.NoError(t, err)

	err = controller.UnlockWallet(30)
	require.NoError(t, err)

	msg := []byte("test message")

	bip322Signature, err := controller.SignBip322NativeSegwit(msg, segwitAddress)
	require.NoError(t, err)

	err = bip322.Verify(msg, bip322Signature, segwitAddress, regtestParams)
	require.NoError(t, err)
}

func TestRecoverAfterRestartDuringWithdrawal(t *testing.T) {
	t.Parallel()
	// need to have at least 300 block on testnet as only then segwit is activated.
	// Mature output is out which has 100 confirmations, which means 200mature outputs
	// will generate 300 blocks
	numMatureOutputs := uint32(200)
	ctx, cancel := context.WithCancel(context.Background())
	tm := StartManager(t, ctx, numMatureOutputs)
	defer tm.Stop(t, cancel)
	tm.insertAllMinedBlocksToBabylon(t)

	cl := tm.Sa.BabylonController()
	params, err := cl.Params()
	require.NoError(t, err)

	testStakingData := tm.getTestStakingData(t, tm.WalletPubKey, params.MinStakingTime, 10000, 1)

	hashed, err := chainhash.NewHash(datagen.GenRandomByteArray(r, 32))
	require.NoError(t, err)
	scr, err := txscript.PayToTaprootScript(tm.CovenantPrivKeys[0].PubKey())
	require.NoError(t, err)
	_, st, erro := tm.Sa.Wallet().TxDetails(hashed, scr)
	// query for exsisting tx is not an error, proper state should be returned
	require.NoError(t, erro)
	require.Equal(t, st, walletcontroller.TxNotFound)

	tm.createAndRegisterFinalityProviders(t, testStakingData)

	txHash := tm.sendStakingTxBTC(t, testStakingData, false)

	go tm.mineNEmptyBlocks(t, params.ConfirmationTimeBlocks, true)
	// must wait for all covenant signatures to be received, to be able to unbond
	tm.waitForStakingTxState(t, txHash, proto.TransactionState_SENT_TO_BABYLON)

	pend, err := tm.BabylonClient.QueryPendingBTCDelegations()
	require.NoError(t, err)
	require.Len(t, pend, 1)
	// need to activate delegation to unbond
	tm.insertCovenantSigForDelegation(t, pend[0])
	tm.waitForStakingTxState(t, txHash, proto.TransactionState_DELEGATION_ACTIVE)

	// Unbond staking transaction and wait for it to be included in mempool
	unbondResponse, err := tm.StakerClient.UnbondStaking(context.Background(), txHash.String())
	require.NoError(t, err)
	unbondingTxHash, err := chainhash.NewHashFromStr(unbondResponse.UnbondingTxHash)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		tx, err := tm.TestRpcClient.GetRawTransaction(unbondingTxHash)
		if err != nil {
			return false
		}

		if tx == nil {
			return false

		}

		return true
	}, 1*time.Minute, eventuallyPollTime)

	ctxAfter, cancelAfter := context.WithCancel(context.Background())
	defer cancelAfter()

	tm.RestartAppWithAction(t, ctxAfter, cancel, func(t *testing.T) {
		// unbodning tx got confirmed during the stop period
		_ = tm.mineNEmptyBlocks(t, staker.UnbondingTxConfirmations+1, false)
	})

	tm.waitForStakingTxState(t, txHash, proto.TransactionState_UNBONDING_CONFIRMED_ON_BTC)
	// it should be possible ot spend from unbonding tx
	tm.spendStakingTxWithHash(t, txHash)
}

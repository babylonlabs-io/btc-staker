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
	"github.com/ory/dockertest/v3"

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
	"github.com/btcsuite/btcd/btcjson"
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

	bitcoindUser = "user"
	bitcoindPass = "pass"
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

func defaultStakerConfigAndBtc(t *testing.T, walletName, passphrase, bitcoindHost string) (*stakercfg.Config, *rpcclient.Client) {
	return defaultStakerConfig(t, walletName, passphrase, bitcoindHost), btcRpcTestClient(t, bitcoindHost)
}

func defaultStakerConfig(t *testing.T, walletName, passphrase, bitcoindHost string) *stakercfg.Config {
	defaultConfig := stakercfg.DefaultConfig()

	// both wallet and node are bicoind
	defaultConfig.BtcNodeBackendConfig.ActiveWalletBackend = types.BitcoindWalletBackend
	defaultConfig.BtcNodeBackendConfig.ActiveNodeBackend = types.BitcoindNodeBackend
	defaultConfig.ActiveNetParams = *regtestParams

	// Fees configuration
	defaultConfig.BtcNodeBackendConfig.FeeMode = "dynamic"
	defaultConfig.BtcNodeBackendConfig.EstimationMode = types.DynamicFeeEstimation

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

	return &defaultConfig
}

func btcRpcTestClient(t *testing.T, bitcoindHost string) *rpcclient.Client {
	testRpcBtcClient, err := rpcclient.New(&rpcclient.ConnConfig{
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
	return testRpcBtcClient
}

type TestManager struct {
	manager *containers.Manager
	TestManagerStakerApp
	TestManagerBTC
}

type TestManagerStakerApp struct {
	Config           *stakercfg.Config
	Db               kvdb.Backend
	Sa               *staker.App
	BabylonClient    *babylonclient.BabylonController
	wg               *sync.WaitGroup
	serviceAddress   string
	StakerClient     *dc.StakerServiceJSONRPCClient
	CovenantPrivKeys []*btcec.PrivateKey
}

type TestManagerBTC struct {
	MinerAddr        btcutil.Address
	BitcoindHandler  *BitcoindTestHandler
	Bitcoind         *dockertest.Resource
	WalletName       string
	WalletPassphrase string
	BitcoindHost     string
	WalletPubKey     *btcec.PublicKey
	WalletAddrInfo   *btcjson.GetAddressInfoResult
	TestRpcBtcClient *rpcclient.Client
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
	stkData := GetTestStakingData(t, stakerKey, stakingTime, stakingAmount, numRestakedFPs, tm.BabylonClient.GetKeyAddress())

	strAddrs := make([]string, numRestakedFPs)
	for i := 0; i < numRestakedFPs; i++ {
		strAddrs[i] = stkData.FinalityProviderBabylonAddrs[i].String()
	}

	_, _, err := tm.manager.BabylondTxBankMultiSend(t, "node0", "1000000ubbn", strAddrs...)
	require.NoError(t, err)
	return stkData
}

func GetTestStakingData(
	t *testing.T,
	stakerKey *btcec.PublicKey,
	stakingTime uint16,
	stakingAmount int64,
	numRestakedFPs int,
	stakerBabylonAddr sdk.AccAddress,
) *testStakingData {
	fpBTCSKs, fpBTCPKs, err := datagen.GenRandomBTCKeyPairs(r, numRestakedFPs)
	require.NoError(t, err)

	fpBBNSKs, fpBBNAddrs := make([]*secp256k1.PrivKey, numRestakedFPs), make([]sdk.AccAddress, numRestakedFPs)
	for i := 0; i < numRestakedFPs; i++ {
		fpBBNSK := secp256k1.GenPrivKey()
		fpAddr := sdk.AccAddress(fpBBNSK.PubKey().Address().Bytes())

		fpBBNSKs[i] = fpBBNSK
		fpBBNAddrs[i] = fpAddr
	}

	return &testStakingData{
		StakerKey: stakerKey,
		// the staker babylon addr needs to be the same one that is going to sign
		// the transaction in the end
		StakerBabylonAddr:               stakerBabylonAddr,
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

func StartManagerBtc(
	t *testing.T,
	ctx context.Context,
	numMatureOutputsInWallet uint32,
	manager *containers.Manager,
) *TestManagerBTC {
	bitcoindHandler := NewBitcoindHandler(t, manager)
	bitcoind := bitcoindHandler.Start()
	passphrase := "pass"
	walletName := "test-wallet"
	_ = bitcoindHandler.CreateWallet(walletName, passphrase)
	// only outputs which are 100 deep are mature
	br := bitcoindHandler.GenerateBlocks(int(numMatureOutputsInWallet) + 100)

	minerAddressDecoded, err := btcutil.DecodeAddress(br.Address, regtestParams)
	require.NoError(t, err)

	bitcoindHost := fmt.Sprintf("127.0.0.1:%s", bitcoind.GetPort("18443/tcp"))
	rpcBtc := btcRpcTestClient(t, bitcoindHost)

	err = rpcBtc.WalletPassphrase(passphrase, 20)
	require.NoError(t, err)

	info, err := rpcBtc.GetAddressInfo(br.Address)
	require.NoError(t, err)

	pubKeyHex := *info.PubKey
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	require.NoError(t, err)

	walletPubKey, err := btcec.ParsePubKey(pubKeyBytes)
	require.NoError(t, err)

	return &TestManagerBTC{
		MinerAddr:        minerAddressDecoded,
		BitcoindHandler:  bitcoindHandler,
		Bitcoind:         bitcoind,
		WalletName:       walletName,
		WalletPassphrase: passphrase,
		BitcoindHost:     bitcoindHost,
		WalletPubKey:     walletPubKey,
		WalletAddrInfo:   info,
		TestRpcBtcClient: rpcBtc,
	}
}

func StartManager(
	t *testing.T,
	ctx context.Context,
	numMatureOutputsInWallet uint32,
) *TestManager {
	manager, err := containers.NewManager(t)
	require.NoError(t, err)

	tmBTC := StartManagerBtc(t, ctx, numMatureOutputsInWallet, manager)

	quorum := 2
	coventantPrivKeys := genCovenants(t, 3)
	tmStakerApp := StartManagerStakerApp(t, ctx, tmBTC, manager, quorum, coventantPrivKeys)

	return &TestManager{
		manager:              manager,
		TestManagerStakerApp: *tmStakerApp,
		TestManagerBTC:       *tmBTC,
	}
}

func StartManagerStakerApp(
	t *testing.T,
	ctx context.Context,
	tmBTC *TestManagerBTC,
	manager *containers.Manager,
	covenantQuorum int,
	coventantPrivKeys []*btcec.PrivateKey,
) *TestManagerStakerApp {
	coventantPubKeys := make([]*btcec.PublicKey, len(coventantPrivKeys))
	for i, cvPrivKey := range coventantPrivKeys {
		coventantPubKeys[i] = cvPrivKey.PubKey()
	}

	var buff bytes.Buffer
	err := regtestParams.GenesisBlock.Header.Serialize(&buff)
	require.NoError(t, err)
	baseHeaderHex := hex.EncodeToString(buff.Bytes())

	pkScript, err := txscript.PayToAddrScript(tmBTC.MinerAddr)
	require.NoError(t, err)

	tmpDir, err := testutil.TempDir(t)
	require.NoError(t, err)
	babylond, err := manager.RunBabylondResource(
		t,
		tmpDir,
		covenantQuorum,
		baseHeaderHex,
		hex.EncodeToString(pkScript), // all slashing will be sent back to wallet
		coventantPubKeys...,
	)
	require.NoError(t, err)

	cfg := defaultStakerConfig(t, tmBTC.WalletName, tmBTC.WalletPassphrase, tmBTC.BitcoindHost)
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
	cfg.WalletConfig.WalletName = ""
	stakerApp, err := staker.NewStakerAppFromConfig(cfg, logger, zapLogger, dbbackend, m)
	require.NoError(t, err)
	// we require separate client to send BTC headers to babylon node (interface does not need this method?)
	bl, err := babylonclient.NewBabylonController(cfg.BabylonConfig, &cfg.ActiveNetParams, logger, zapLogger)
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

	fmt.Printf("\n log config %+v", cfg)

	return &TestManagerStakerApp{
		Config:           cfg,
		Db:               dbbackend,
		Sa:               stakerApp,
		BabylonClient:    bl,
		wg:               &wg,
		serviceAddress:   addressString,
		StakerClient:     stakerClient,
		CovenantPrivKeys: coventantPrivKeys,
	}
}

func genCovenants(t *testing.T, numCovenants int) []*btcec.PrivateKey {
	var coventantPrivKeys []*btcec.PrivateKey
	for i := 0; i < numCovenants; i++ {
		covenantPrivKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		coventantPrivKeys = append(coventantPrivKeys, covenantPrivKey)
	}
	return coventantPrivKeys
}

func (tm *TestManager) Stop(t *testing.T, cancelFunc context.CancelFunc) {
	cancelFunc()
	tm.wg.Wait()
	err := tm.manager.ClearResources()
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

		block1, err := tm.TestRpcBtcClient.GetBlock(block1Hash)
		require.NoError(t, err)
		block2, err := tm.TestRpcBtcClient.GetBlock(block2Hash)
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

func (tm *TestManager) createAndRegisterFinalityProviders(t *testing.T, stkData *testStakingData) {
	params, err := tm.BabylonClient.QueryStakingTracker()
	require.NoError(t, err)

	for i := 0; i < stkData.GetNumRestakedFPs(); i++ {
		// ensure the finality provider in testStakingData does not exist yet
		fpResp, err := tm.BabylonClient.QueryFinalityProvider(stkData.FinalityProviderBtcKeys[i])
		require.Nil(t, fpResp)
		require.Error(t, err)
		require.True(t, errors.Is(err, babylonclient.ErrFinalityProviderDoesNotExist))

		pop, err := btcstypes.NewPoPBTC(stkData.FinalityProviderBabylonAddrs[i], stkData.FinalityProviderBtcPrivKeys[i])
		require.NoError(t, err)

		btcFpKey := bbntypes.NewBIP340PubKeyFromBTCPK(stkData.FinalityProviderBtcKeys[i])

		// get current finality providers
		resp, err := tm.BabylonClient.QueryFinalityProviders(100, 0)
		require.NoError(t, err)
		// register the generated finality provider
		err = tm.BabylonClient.RegisterFinalityProvider(
			stkData.FinalityProviderBabylonAddrs[i],
			stkData.FinalityProviderBabylonPrivKeys[i],
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
		header, err := tm.TestRpcBtcClient.GetBlockHeader(hash)
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
	header, err := tm.TestRpcBtcClient.GetBlock(hash)
	require.NoError(t, err)
	return header
}

func (tm *TestManager) sendStakingTxBTC(
	t *testing.T,
	stkData *testStakingData,
	sendToBabylonFirst bool,
) *chainhash.Hash {
	fpBTCPKs := []string{}
	for i := 0; i < stkData.GetNumRestakedFPs(); i++ {
		fpBTCPK := hex.EncodeToString(schnorr.SerializePubKey(stkData.FinalityProviderBtcKeys[i]))
		fpBTCPKs = append(fpBTCPKs, fpBTCPK)
	}
	res, err := tm.StakerClient.Stake(
		context.Background(),
		tm.MinerAddr.String(),
		stkData.StakingAmount,
		fpBTCPKs,
		int64(stkData.StakingTime),
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
			txFromMempool := retrieveTransactionFromMempool(t, tm.TestRpcBtcClient, []*chainhash.Hash{hashFromString})
			return len(txFromMempool) == 1
		}, eventuallyWaitTimeOut, eventuallyPollTime)

		mBlock := tm.mineBlock(t)
		require.Equal(t, 2, len(mBlock.Transactions))

		_, err = tm.BabylonClient.InsertBtcBlockHeaders([]*wire.BlockHeader{&mBlock.Header})
		require.NoError(t, err)
	}
	return hashFromString
}

func (tm *TestManager) sendMultipleStakingTx(t *testing.T, tStkData []*testStakingData, sendToBabylonFirst bool) []*chainhash.Hash {
	var hashes []*chainhash.Hash
	for _, data := range tStkData {
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
	tStkData *testStakingData,
	params *babylonclient.StakingParams,
) *chainhash.Hash {
	unbondingTme := uint16(params.FinalizationTimeoutBlocks) + 1

	stakingInfo, err := staking.BuildStakingInfo(
		tStkData.StakerKey,
		tStkData.FinalityProviderBtcKeys,
		params.CovenantPks,
		params.CovenantQuruomThreshold,
		tStkData.StakingTime,
		btcutil.Amount(tStkData.StakingAmount),
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
		tx, err := tm.TestRpcBtcClient.GetRawTransaction(&txHash)
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
		tStkData.StakerKey,
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
	unbondingAmount := btcutil.Amount(tStkData.StakingAmount) - unbondingFee

	unbondingInfo, err := staking.BuildUnbondingInfo(
		tStkData.StakerKey,
		tStkData.FinalityProviderBtcKeys,
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
		tStkData.StakerKey,
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

	babylonAddrHash := tmhash.Sum(tStkData.StakerBabylonAddr.Bytes())

	sig, err := tm.Sa.Wallet().SignBip322NativeSegwit(babylonAddrHash, tm.MinerAddr)
	require.NoError(t, err)

	pop, err := babylonclient.NewBabylonBip322Pop(
		babylonAddrHash,
		sig,
		tm.MinerAddr,
	)
	require.NoError(t, err)

	fpBTCPKs := []string{}
	for i := 0; i < tStkData.GetNumRestakedFPs(); i++ {
		fpBTCPK := hex.EncodeToString(schnorr.SerializePubKey(tStkData.FinalityProviderBtcKeys[i]))
		fpBTCPKs = append(fpBTCPKs, fpBTCPK)
	}
	_, err = tm.StakerClient.WatchStaking(
		context.Background(),
		hex.EncodeToString(serializedStakingTx),
		int(tStkData.StakingTime),
		int(tStkData.StakingAmount),
		hex.EncodeToString(schnorr.SerializePubKey(tStkData.StakerKey)),
		fpBTCPKs,
		hex.EncodeToString(serializedSlashingTx),
		hex.EncodeToString(slashingSigResult.Signature.Serialize()),
		tStkData.StakerBabylonAddr.String(),
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

	txs := retrieveTransactionFromMempool(t, tm.TestRpcBtcClient, []*chainhash.Hash{&txHash})
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
		txFromMempool := retrieveTransactionFromMempool(t, tm.TestRpcBtcClient, []*chainhash.Hash{spendTxHash})
		return len(txFromMempool) == 1
	}, eventuallyWaitTimeOut, eventuallyPollTime)

	sendTx := retrieveTransactionFromMempool(t, tm.TestRpcBtcClient, []*chainhash.Hash{spendTxHash})[0]

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
	}, 2*time.Minute, eventuallyPollTime)
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
	headers := GetAllMinedBtcHeadersSinceGenesis(t, tm.TestRpcBtcClient)
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
	require.NoError(t, err)

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

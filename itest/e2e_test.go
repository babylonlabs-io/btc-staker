//go:build e2e
// +build e2e

package e2etest

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/babylonlabs-io/btc-staker/babylonclient/keyringcontroller"
	"github.com/babylonlabs-io/btc-staker/itest/containers"
	"github.com/babylonlabs-io/btc-staker/itest/testutil"
	"github.com/babylonlabs-io/networks/parameters/parser"

	"github.com/babylonlabs-io/babylon/v3/btcstaking"
	"github.com/babylonlabs-io/babylon/v3/crypto/bip322"
	btcctypes "github.com/babylonlabs-io/babylon/v3/x/btccheckpoint/types"

	"github.com/babylonlabs-io/babylon/v3/testutil/datagen"
	bbntypes "github.com/babylonlabs-io/babylon/v3/types"
	"github.com/babylonlabs-io/btc-staker/staker"
	"github.com/babylonlabs-io/btc-staker/stakercfg"
	"github.com/babylonlabs-io/btc-staker/types"
	"github.com/babylonlabs-io/btc-staker/walletcontroller"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

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
	)
	require.Error(t, err)

	// No provider key
	_, err = tm.StakerClient.Stake(
		context.Background(),
		tm.MinerAddr.String(),
		testStakingData.StakingAmount,
		[]string{},
		int64(testStakingData.StakingTime),
	)
	require.Error(t, err)
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

	testStakingData := tm.getTestStakingData(t, tm.WalletPubKey, params.MinStakingTime, 100000, 1)

	// since transaction never sent to bitcoin,
	// tx is not found
	hashed, err := chainhash.NewHash(datagen.GenRandomByteArray(r, 32))
	require.NoError(t, err)
	scr, err := txscript.PayToTaprootScript(tm.CovenantPrivKeys[0].PubKey())
	require.NoError(t, err)
	_, st, erro := tm.Sa.Wallet().TxDetails(hashed, scr)
	// query for exsisting tx is not an error, proper state should be returned
	require.NoError(t, erro)
	require.Equal(t, st, walletcontroller.TxNotFound)

	tm.createAndRegisterFinalityProviders(t, testStakingData)

	txHash := tm.sendStakingTxBTC(t, testStakingData)

	go tm.mineNEmptyBlocks(t, params.ConfirmationTimeBlocks, true)
	tm.waitForStakingTxState(t, txHash, staker.BabylonPendingStatus)

	pend, err := tm.BabylonClient.QueryPendingBTCDelegations()
	require.NoError(t, err)
	require.Len(t, pend, 1)
	// need to activate delegation to unbond
	tm.insertCovenantSigForDelegation(t, pend[0])
	tm.waitForStakingTxState(t, txHash, staker.BabylonVerifiedStatus)

	require.Eventually(t, func() bool {
		txFromMempool := retrieveTransactionFromMempool(t, tm.TestRpcBtcClient, []*chainhash.Hash{txHash})
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
	tm.waitForStakingTxState(t, txHash, staker.BabylonActiveStatus)

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
		tx, err := tm.TestRpcBtcClient.GetRawTransaction(unbondingTxHash)
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
	tm.mineNEmptyBlocks(t, staker.UnbondingTxConfirmations, false)
	tm.waitForUnbondingTxConfirmedOnBtc(t, txHash, unbondingTxHash)

	// Spend unbonding tx of pre-approval stake
	require.Eventually(t, func() bool {
		withdrawableTransactionsResp, err = tm.StakerClient.WithdrawableTransactions(context.Background(), nil, nil)
		if err != nil {
			return false
		}
		if len(withdrawableTransactionsResp.Transactions) != 1 {
			return false
		}

		return true
	}, 1*time.Minute, eventuallyPollTime)

	// We can spend unbonding tx immediately as in e2e test, min unbonding time is 5 blocks and we locked it
	// for 5 blocks, but to consider unbonding tx as confirmed we need to wait for 6 blocks
	// so at this point time lock should already have passed
	tm.spendStakingTxWithHash(t, txHash)
	tm.mineNEmptyBlocks(t, staker.UnbondingTxConfirmations, false)
	tm.waitForTxOutputSpent(t, unbondingTxHash)
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
	txHashes := tm.sendMultipleStakingTxBTC(t, []*testStakingData{
		testStakingData1,
		testStakingData2,
		testStakingData3,
	})

	for _, txHash := range txHashes {
		txHash := txHash
		tm.waitForStakingTxState(t, txHash, staker.BabylonPendingStatus)
	}

	pend, err := tm.BabylonClient.QueryPendingBTCDelegations()
	require.NoError(t, err)
	require.Len(t, pend, 3)
	tm.insertCovenantSigForDelegation(t, pend[0])
	tm.insertCovenantSigForDelegation(t, pend[1])
	tm.insertCovenantSigForDelegation(t, pend[2])

	for _, txHash := range txHashes {
		txHash := txHash
		tm.waitForStakingTxState(t, txHash, staker.BabylonVerifiedStatus)
	}

	// Ultimately we will get 3 tx in the mempool meaning all staking transactions
	// use valid inputs
	require.Eventually(t, func() bool {
		txFromMempool := retrieveTransactionFromMempool(t, tm.TestRpcBtcClient, txHashes)
		return len(txFromMempool) == 3
	}, eventuallyWaitTimeOut, eventuallyPollTime)
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
	scfg.WalletConfig.WalletName = ""
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
	cfg, c := defaultStakerConfigAndBtc(t, walletName, passphrase, rpcHost)

	segwitAddress, err := c.GetNewAddress("")
	require.NoError(t, err)
	cfg.WalletConfig.WalletName = ""
	controller, err := walletcontroller.NewRPCWalletController(cfg)
	require.NoError(t, err)

	err = controller.UnlockWallet(30)
	require.NoError(t, err)

	msg := []byte("test message")

	bip322Signature, err := controller.SignBip322Signature(msg, segwitAddress)
	require.NoError(t, err)

	err = bip322.Verify(msg, bip322Signature, segwitAddress, regtestParams)
	require.NoError(t, err)
}

func TestStakeFromPhase1(t *testing.T) {
	t.Parallel()
	numMatureOutputsInWallet := uint32(200)
	ctx, cancel := context.WithCancel(context.Background())
	manager, err := containers.NewManager(t)
	require.NoError(t, err)

	tmBTC := StartManagerBtc(t, ctx, numMatureOutputsInWallet, manager)

	minStakingTime := uint16(100)
	stakerAddr := datagen.GenRandomAccount().GetAddress()
	testStakingData := GetTestStakingData(t, tmBTC.WalletPubKey, minStakingTime, 10000, 1, stakerAddr)

	fpPkHex := hex.EncodeToString(schnorr.SerializePubKey(testStakingData.FinalityProviderBtcKeys[0]))
	btcStakerPkHex := hex.EncodeToString(schnorr.SerializePubKey(testStakingData.StakerKey))

	appCli := testutil.TestApp()

	coventantPrivKeys := genCovenants(t, 1)
	covenantPkSerializedHex := hex.EncodeToString(schnorr.SerializePubKey(coventantPrivKeys[0].PubKey()))
	covenantPkHex := hex.EncodeToString(coventantPrivKeys[0].PubKey().SerializeCompressed())

	lastParams := &parser.VersionedGlobalParams{
		Version:          0,
		ActivationHeight: 100,
		StakingCap:       3000000,
		CapHeight:        0,
		Tag:              "01020304",
		CovenantPks: []string{
			covenantPkHex,
		},
		CovenantQuorum:    1,
		UnbondingTime:     1000,
		UnbondingFee:      1000,
		MaxStakingAmount:  300000,
		MinStakingAmount:  3000,
		MaxStakingTime:    10000,
		MinStakingTime:    100,
		ConfirmationDepth: 10,
	}

	globalParams := parser.GlobalParams{
		Versions: []*parser.VersionedGlobalParams{
			lastParams,
		},
	}

	globalParamsMarshalled, err := json.Marshal(globalParams)
	require.NoError(t, err)

	paramsFilePath := testutil.CreateTempFileWithData(t, "tmpParams-*.json", globalParamsMarshalled)
	stakingAmount := lastParams.MaxStakingAmount - 1
	inclusionHeight := lastParams.ActivationHeight + 1
	stakingTime := lastParams.MaxStakingTime

	commonFlags := []string{
		fmt.Sprintf("--covenant-committee-pks=%s", covenantPkSerializedHex),
		fmt.Sprintf("--tag=%s", lastParams.Tag),
		"--covenant-quorum=1", "--network=regtest",
	}

	createTxCmdArgs := []string{
		paramsFilePath,
		fmt.Sprintf("--staker-pk=%s", btcStakerPkHex),
		fmt.Sprintf("--finality-provider-pk=%s", fpPkHex),
		fmt.Sprintf("--staking-amount=%d", stakingAmount),
		fmt.Sprintf("--tx-inclusion-height=%d", inclusionHeight),
		fmt.Sprintf("--staking-time=%d", stakingTime),
	}
	resP1StkTx := testutil.AppRunCreatePhase1StakingTxWithParams(r, t, appCli, append(createTxCmdArgs, commonFlags...))
	require.NotNil(t, resP1StkTx)

	stkTx, err := hex.DecodeString(resP1StkTx.StakingTxHex)
	require.NoError(t, err)

	var tx wire.MsgTx
	rbuf := bytes.NewReader(stkTx)
	err = tx.DeserializeNoWitness(rbuf)
	require.NoError(t, err)

	rpcBtc := tmBTC.TestRpcBtcClient
	err = rpcBtc.WalletPassphrase(tmBTC.WalletPassphrase, 20)
	require.NoError(t, err)

	resFundRawStkTx, err := rpcBtc.FundRawTransaction(&tx, btcjson.FundRawTransactionOpts{
		FeeRate: btcjson.Float64(0.02),
		// by setting the ChangePosition to 1 we make sure that the staking output will be at index 0
		ChangePosition: btcjson.Int(1),
	}, btcjson.Bool(false))
	require.NoError(t, err)
	require.NotNil(t, resFundRawStkTx)

	signedStkTx, complete, err := rpcBtc.SignRawTransactionWithWallet(resFundRawStkTx.Transaction)
	require.True(t, complete)
	require.NoError(t, err)
	require.NotNil(t, signedStkTx)

	txHash, err := rpcBtc.SendRawTransaction(signedStkTx, false)
	require.NoError(t, err)
	require.NotNil(t, txHash)
	require.Equal(t, txHash.String(), signedStkTx.TxHash().String())

	tmBTC.BitcoindHandler.GenerateBlocks(15)

	stkTxResult, err := rpcBtc.GetTransaction(txHash)
	require.NoError(t, err)
	require.NotNil(t, stkTxResult)

	parsedGlobalParams, err := parser.ParseGlobalParams(&globalParams)
	require.NoError(t, err)

	lastParamsVersioned := parsedGlobalParams.Versions[len(parsedGlobalParams.Versions)-1]

	// Makes sure it is able to parse the staking tx
	paserdStkTx, err := btcstaking.ParseV0StakingTx(
		signedStkTx,
		lastParamsVersioned.Tag,
		lastParamsVersioned.CovenantPks,
		lastParamsVersioned.CovenantQuorum,
		regtestParams,
	)
	require.NoError(t, err)
	require.NotNil(t, paserdStkTx)

	// at this point the BTC staking transaction is confirmed and was mined in BTC
	// so the babylon chain can start and try to transition this staking BTC tx
	// into a babylon BTC delegation in the cosmos side.
	tmStakerApp := StartManagerStakerApp(t, ctx, tmBTC, manager, 1, coventantPrivKeys)

	tm := &TestManager{
		manager:              manager,
		TestManagerStakerApp: *tmStakerApp,
		TestManagerBTC:       *tmBTC,
	}
	defer tm.Stop(t, cancel)

	tm.manager.WaitForNextBabylonBlock(t)

	// verify that the chain is healthy
	require.Eventually(t, func() bool {
		_, err := tm.BabylonClient.Params()
		return err == nil
	}, time.Minute, 200*time.Millisecond)

	// funds the fpd
	_, _, err = tm.manager.BabylondTxBankMultiSend(t, "node0", "1000000ubbn", testStakingData.FinalityProviderBabylonAddrs[0].String())
	require.NoError(t, err)

	tm.insertAllMinedBlocksToBabylon(t)
	tm.createAndRegisterFinalityProviders(t, testStakingData)

	stakerAddrStr := tmBTC.MinerAddr.String()
	stkTxHash := signedStkTx.TxHash().String()

	argsStkFromPhase1 := []string{
		fmt.Sprintf("--daemon-address=tcp://%s", tm.serviceAddress),
		fmt.Sprintf("--staker-address=%s", stakerAddrStr),
		fmt.Sprintf("--staking-transaction-hash=%s", stkTxHash),
		fmt.Sprintf("--tx-inclusion-height=%d", inclusionHeight),
	}
	err = testutil.AppRunStakeFromPhase1(r, t, appCli, argsStkFromPhase1)
	require.NoError(t, err)

	// wait for BTC delegation to become active
	cl := tm.Sa.BabylonController()
	params, err := cl.Params()
	require.NoError(t, err)

	tm.mineNEmptyBlocks(t, params.ConfirmationTimeBlocks+1, true)

	pend, err := tm.BabylonClient.QueryPendingBTCDelegations()
	require.NoError(t, err)
	require.Len(t, pend, 1)

	tm.insertCovenantSigForDelegation(t, pend[0])

	delInfo, err := tm.BabylonClient.QueryBTCDelegation(txHash)
	require.NoError(t, err)
	require.True(t, delInfo.BtcDelegation.Active)
}

func TestPopCreation(t *testing.T) {
	t.Parallel()
	manager, err := containers.NewManager(t)
	require.NoError(t, err)
	h := NewBitcoindHandler(t, manager)
	bitcoind := h.Start()
	passphrase := "pass"
	walletName := "test-wallet"
	_ = h.CreateWallet(walletName, passphrase)

	rpcHost := fmt.Sprintf("127.0.0.1:%s", bitcoind.GetPort("18443/tcp"))
	cfg, c := defaultStakerConfigAndBtc(t, walletName, passphrase, rpcHost)

	segwitAddress, err := c.GetNewAddress("")
	require.NoError(t, err)
	cfg.WalletConfig.WalletName = ""
	controller, err := walletcontroller.NewRPCWalletController(cfg)
	require.NoError(t, err)

	keyring, err := keyringcontroller.CreateKeyring(
		// does not matter for memory keyring
		"/",
		"babylon",
		"memory",
		nil,
	)
	require.NoError(t, err)

	randomKey, _ := btcec.NewPrivateKey()
	require.NoError(t, err)

	keyName := "test"
	err = keyring.ImportPrivKeyHex(keyName, hex.EncodeToString(randomKey.Serialize()), "secp256k1")
	require.NoError(t, err)

	record, err := keyring.Key(keyName)
	require.NoError(t, err)

	address, err := record.GetAddress()
	require.NoError(t, err)

	popCreator := staker.NewPopCreator(controller, keyring)
	require.NotNil(t, popCreator)

	err = controller.UnlockWallet(30)
	require.NoError(t, err)

	popResponse, err := popCreator.CreatePop(segwitAddress, "bbn", address)
	require.NoError(t, err)
	require.NotNil(t, popResponse)
}

func TestPopCreationTaprootAddress(t *testing.T) {
	t.Parallel()
	manager, err := containers.NewManager(t)
	require.NoError(t, err)
	h := NewBitcoindHandler(t, manager)
	bitcoind := h.Start()
	passphrase := "pass"
	walletName := "test-wallet"
	_ = h.CreateWallet(walletName, passphrase)

	rpcHost := fmt.Sprintf("127.0.0.1:%s", bitcoind.GetPort("18443/tcp"))
	cfg, c := defaultStakerConfigAndBtc(t, walletName, passphrase, rpcHost)

	// 'bech32m' is taproot address as defined in bip86: https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki
	taprootAddress, err := c.GetNewAddressType("", "bech32m")
	require.NoError(t, err)
	cfg.WalletConfig.WalletName = ""
	controller, err := walletcontroller.NewRPCWalletController(cfg)
	require.NoError(t, err)

	keyring, err := keyringcontroller.CreateKeyring(
		// does not matter for memory keyring
		"/",
		"babylon",
		"memory",
		nil,
	)
	require.NoError(t, err)

	randomKey, _ := btcec.NewPrivateKey()
	require.NoError(t, err)

	keyName := "test"
	err = keyring.ImportPrivKeyHex(keyName, hex.EncodeToString(randomKey.Serialize()), "secp256k1")
	require.NoError(t, err)

	record, err := keyring.Key(keyName)
	require.NoError(t, err)

	address, err := record.GetAddress()
	require.NoError(t, err)

	popCreator := staker.NewPopCreator(controller, keyring)
	require.NotNil(t, popCreator)

	err = controller.UnlockWallet(30)
	require.NoError(t, err)

	popResponse, err := popCreator.CreatePop(taprootAddress, "bbn", address)
	require.NoError(t, err)
	require.NotNil(t, popResponse)
}

func containsOutput(outputs []walletcontroller.Utxo, address string, amount btcutil.Amount) bool {
	for _, o := range outputs {
		if o.Address == address && o.Amount == amount {
			return true
		}
	}
	return false
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

	testStakingData := tm.getTestStakingData(t, tm.WalletPubKey, params.MinStakingTime, 100000, 1)

	hashed, err := chainhash.NewHash(datagen.GenRandomByteArray(r, 32))
	require.NoError(t, err)
	scr, err := txscript.PayToTaprootScript(tm.CovenantPrivKeys[0].PubKey())
	require.NoError(t, err)
	_, st, erro := tm.Sa.Wallet().TxDetails(hashed, scr)
	// query for exsisting tx is not an error, proper state should be returned
	require.NoError(t, erro)
	require.Equal(t, st, walletcontroller.TxNotFound)

	tm.createAndRegisterFinalityProviders(t, testStakingData)

	txHash := tm.sendStakingTxBTC(t, testStakingData)

	go tm.mineNEmptyBlocks(t, params.ConfirmationTimeBlocks, true)
	// must wait for all covenant signatures to be received, to be able to unbond
	tm.waitForStakingTxState(t, txHash, staker.BabylonPendingStatus)

	pend, err := tm.BabylonClient.QueryPendingBTCDelegations()
	require.NoError(t, err)
	require.Len(t, pend, 1)
	// need to activate delegation to unbond
	tm.insertCovenantSigForDelegation(t, pend[0])
	tm.waitForStakingTxState(t, txHash, staker.BabylonVerifiedStatus)

	require.Eventually(t, func() bool {
		txFromMempool := retrieveTransactionFromMempool(t, tm.TestRpcBtcClient, []*chainhash.Hash{txHash})
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
	tm.waitForStakingTxState(t, txHash, staker.BabylonActiveStatus)

	// Unbond staking transaction and wait for it to be included in mempool
	unbondResponse, err := tm.StakerClient.UnbondStaking(context.Background(), txHash.String())
	require.NoError(t, err)
	unbondingTxHash, err := chainhash.NewHashFromStr(unbondResponse.UnbondingTxHash)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		tx, err := tm.TestRpcBtcClient.GetRawTransaction(unbondingTxHash)
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

	tm.waitForUnbondingTxConfirmedOnBtc(t, txHash, unbondingTxHash)
	// it should be possible ot spend from unbonding tx
	tm.spendStakingTxWithHash(t, txHash)
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

	txHash := tm.sendStakingTxBTC(t, testStakingData)

	go tm.mineNEmptyBlocks(t, params.ConfirmationTimeBlocks, true)
	tm.waitForStakingTxState(t, txHash, staker.BabylonPendingStatus)
	require.NoError(t, err)

	pend, err := tm.BabylonClient.QueryPendingBTCDelegations()
	require.NoError(t, err)
	require.Len(t, pend, 1)
	// need to activate delegation to unbond
	tm.insertCovenantSigForDelegation(t, pend[0])
	tm.waitForStakingTxState(t, txHash, staker.BabylonVerifiedStatus)

	require.Eventually(t, func() bool {
		txFromMempool := retrieveTransactionFromMempool(t, tm.TestRpcBtcClient, []*chainhash.Hash{txHash})
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
	tm.waitForStakingTxState(t, txHash, staker.BabylonActiveStatus)

	resp, err := tm.StakerClient.UnbondStaking(context.Background(), txHash.String())
	require.NoError(t, err)

	unbondingTxHash, err := chainhash.NewHashFromStr(resp.UnbondingTxHash)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		tx, err := tm.TestRpcBtcClient.GetRawTransaction(unbondingTxHash)
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

	tm.mineNEmptyBlocks(t, staker.UnbondingTxConfirmations, false)
	tm.waitForUnbondingTxConfirmedOnBtc(t, txHash, unbondingTxHash)

	require.Eventually(t, func() bool {
		withdrawableTransactionsResp, err := tm.StakerClient.WithdrawableTransactions(context.Background(), nil, nil)
		if err != nil {
			return false
		}
		if len(withdrawableTransactionsResp.Transactions) != 1 {
			return false
		}

		return true
	}, 1*time.Minute, eventuallyPollTime)

	// We can spend unbonding tx immediately as in e2e test, min unbonding time is 5 blocks and we locked it
	// for 5 blocks, but to consider unbonding tx as confirmed we need to wait for 6 blocks
	// so at this point time lock should already have passed
	tm.spendStakingTxWithHash(t, txHash)
	tm.mineNEmptyBlocks(t, staker.SpendStakeTxConfirmations, false)
	tm.waitForTxOutputSpent(t, unbondingTxHash)
}

func TestStakeExpansion(t *testing.T) {
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
	originalStakingAmount := int64(50000)
	expandedStakingAmount := int64(100000)

	// Create test data for original staking
	testStakingData := tm.getTestStakingData(t, tm.WalletPubKey, stakingTime, originalStakingAmount, 1)
	tm.createAndRegisterFinalityProviders(t, testStakingData)

	// Step 1: Create and activate initial BTC delegation
	originalTxHash := tm.sendStakingTxBTC(t, testStakingData)

	go tm.mineNEmptyBlocks(t, params.ConfirmationTimeBlocks, true)
	tm.waitForStakingTxState(t, originalTxHash, staker.BabylonPendingStatus)

	pend, err := tm.BabylonClient.QueryPendingBTCDelegations()
	require.NoError(t, err)
	require.Len(t, pend, 1)

	// Need to activate delegation before expansion
	tm.insertCovenantSigForDelegation(t, pend[0])
	tm.waitForStakingTxState(t, originalTxHash, staker.BabylonVerifiedStatus)

	require.Eventually(t, func() bool {
		txFromMempool := retrieveTransactionFromMempool(t, tm.TestRpcBtcClient, []*chainhash.Hash{originalTxHash})
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
		*originalTxHash,
		proof,
	)
	require.NoError(t, err)
	tm.waitForStakingTxState(t, originalTxHash, staker.BabylonActiveStatus)

	// Step 2: Send MsgBtcStakeExpand
	fpKeys := make([]string, len(testStakingData.FinalityProviderBtcKeys))
	for i, fpKey := range testStakingData.FinalityProviderBtcKeys {
		fpKeys[i] = hex.EncodeToString(schnorr.SerializePubKey(fpKey))
	}

	expansionResp, err := tm.StakerClient.StakeExpand(
		context.Background(),
		tm.MinerAddr.String(),
		expandedStakingAmount,
		fpKeys,
		int64(stakingTime),
		originalTxHash.String(),
	)
	require.NoError(t, err)

	expansionTxHash, err := chainhash.NewHashFromStr(expansionResp.TxHash)
	require.NoError(t, err)

	// Step 3: Verify new BTC delegation is pending
	tm.waitForStakingTxState(t, expansionTxHash, staker.BabylonPendingStatus)

	pendingDel, err := tm.BabylonClient.QueryPendingBTCDelegations()
	require.NoError(t, err)
	require.Len(t, pendingDel, 1)
	require.NotNil(t, pendingDel[0].StkExp)

	// Step 4: Covenant signatures for expansion
	tm.insertCovenantSigForDelegation(t, pendingDel[0])
	tm.waitForStakingTxState(t, expansionTxHash, staker.BabylonVerifiedStatus)

	// stake expansion delegation should be in verified sate
	verifiedDel, err := tm.BabylonClient.QueryVerifiedBTCDelegations()
	require.NoError(t, err)
	require.Len(t, verifiedDel, 1)
	require.NotNil(t, verifiedDel[0].StkExp)

	// Step 5: Wait for expansion transaction to be submitted to Bitcoin mempool
	require.Eventually(t, func() bool {
		txFromMempool := retrieveTransactionFromMempool(t, tm.TestRpcBtcClient, []*chainhash.Hash{expansionTxHash})
		return len(txFromMempool) == 1
	}, eventuallyWaitTimeOut, eventuallyPollTime)

	// Step 6: Mine the expansion transaction
	expansionBlock := tm.mineBlock(t)
	require.Equal(t, 2, len(expansionBlock.Transactions))

	expansionHeaderBytes := bbntypes.NewBTCHeaderBytesFromBlockHeader(&expansionBlock.Header)
	expansionTxInclProof, err := btcctypes.SpvProofFromHeaderAndTransactions(&expansionHeaderBytes, txsToBytes(expansionBlock.Transactions), 1)
	require.NoError(t, err)

	_, err = tm.BabylonClient.InsertBtcBlockHeaders([]*wire.BlockHeader{&expansionBlock.Header})
	require.NoError(t, err)

	// Step 7: Wait for the expansion transaction to be k-deep on Bitcoin
	tm.mineNEmptyBlocks(t, staker.UnbondingTxConfirmations, true)
	require.Eventually(t, func() bool {
		// Get transaction details and verify confirmations
		res, err := tm.Sa.Wallet().TxVerbose(expansionTxHash)
		if err != nil {
			return false
		}
		// Check if we have the required number of confirmations
		return res.Confirmations >= staker.UnbondingTxConfirmations
	}, eventuallyWaitTimeOut, eventuallyPollTime)

	// Step 8: Report expansion transaction via MsgBTCUndelegate for the original delegation
	rawStkExpTransaction, err := tm.TestRpcBtcClient.GetRawTransaction(expansionTxHash)
	require.NoError(t, err)
	expansionMsgTx := rawStkExpTransaction.MsgTx()

	// get funding txs for the stake expansion
	var fundingTxs [][]byte
	for _, txIn := range expansionMsgTx.TxIn {
		rawTransaction, err := tm.TestRpcBtcClient.GetRawTransaction(&txIn.PreviousOutPoint.Hash)
		require.NoError(t, err)

		serializedTx, err := bbntypes.SerializeBTCTx(rawTransaction.MsgTx())
		require.NoError(t, err)

		fundingTxs = append(fundingTxs, serializedTx)
	}

	err = tm.BabylonClient.ReportUnbonding(
		*originalTxHash,
		expansionMsgTx,
		expansionTxInclProof,
		fundingTxs,
	)
	require.NoError(t, err)

	// Step 9: Wait for expansion to be active
	// Verify the original delegation is no longer active
	// and the expansion delegation is active
	tm.waitForStakingTxState(t, expansionTxHash, staker.BabylonActiveStatus)

	originalDelegation, err := tm.BabylonClient.QueryBTCDelegation(originalTxHash)
	require.NoError(t, err)
	require.False(t, originalDelegation.BtcDelegation.Active)

	expansionDelegation, err := tm.BabylonClient.QueryBTCDelegation(expansionTxHash)
	require.NoError(t, err)
	require.True(t, expansionDelegation.BtcDelegation.Active)

	// Verify the expansion delegation has the expected larger amount
	require.True(t, expansionDelegation.BtcDelegation.TotalSat > originalDelegation.BtcDelegation.TotalSat)
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

	testStakingData1 := tm.getTestStakingData(t, tm.WalletPubKey, stakingTime1, 100000, 1)
	testStakingData2 := testStakingData1.withStakingTime(stakingTime2)
	testStakingData3 := testStakingData1.withStakingTime(stakingTime3)
	testStakingData4 := testStakingData1.withStakingTime(stakingTime4)
	testStakingData5 := testStakingData1.withStakingTime(stakingTime5)

	tm.createAndRegisterFinalityProviders(t, testStakingData1)
	txHashes := tm.sendMultipleStakingTxBTC(t, []*testStakingData{
		testStakingData1,
		testStakingData2,
		testStakingData3,
		testStakingData4,
		testStakingData5,
	})

	go tm.mineNEmptyBlocks(t, params.ConfirmationTimeBlocks, true)

	for _, txHash := range txHashes {
		tm.waitForStakingTxState(t, txHash, staker.BabylonPendingStatus)
	}

	pends, err := tm.BabylonClient.QueryPendingBTCDelegations()
	require.NoError(t, err)

	// need to activate delegation
	for _, pend := range pends {
		tm.insertCovenantSigForDelegation(t, pend)
	}

	for _, txHash := range txHashes {
		tm.waitForStakingTxState(t, txHash, staker.BabylonVerifiedStatus)
	}

	require.Eventually(t, func() bool {
		txFromMempool := retrieveTransactionFromMempool(t, tm.TestRpcBtcClient, txHashes)
		return len(txFromMempool) == 5
	}, eventuallyWaitTimeOut, eventuallyPollTime)

	mBlock := tm.mineBlock(t)
	// more than 1 transaction is mined (coinbase tx and staking txs)
	require.Equal(t, 1+len(txHashes), len(mBlock.Transactions))

	headerBytes := bbntypes.NewBTCHeaderBytesFromBlockHeader(&mBlock.Header)

	proofs := make([]*btcctypes.BTCSpvProof, len(mBlock.Transactions))
	for i := range mBlock.Transactions {
		if i == 0 { // skip coinbase
			continue
		}
		proof, err := btcctypes.SpvProofFromHeaderAndTransactions(
			&headerBytes,
			txsToBytes(mBlock.Transactions),
			uint(i),
		)
		require.NoError(t, err)
		proofs[i] = proof
	}

	_, err = tm.BabylonClient.InsertBtcBlockHeaders([]*wire.BlockHeader{&mBlock.Header})
	require.NoError(t, err)

	tm.mineNEmptyBlocks(t, params.ConfirmationTimeBlocks, true)

	for i, tx := range mBlock.Transactions {
		if i == 0 { // skip coinbase
			continue
		}
		_, err = tm.BabylonClient.ActivateDelegation(
			tx.TxHash(),
			proofs[i],
		)
		require.NoError(t, err)
	}

	for _, txHash := range txHashes {
		tm.waitForStakingTxState(t, txHash, staker.BabylonActiveStatus)
	}

	// mine enough block so that:
	// stakingTime1, stakingTime3, stakingTime4 are spendable
	blockForStakingToExpire := uint32(testStakingData4.StakingTime) - params.ConfirmationTimeBlocks - 1
	tm.mineNEmptyBlocks(t, blockForStakingToExpire, false)

	require.Eventually(t, func() bool {
		withdrawableTransactionsResp, err := tm.StakerClient.WithdrawableTransactions(context.Background(), nil, nil)
		require.NoError(t, err)
		return len(withdrawableTransactionsResp.Transactions) == 3
	}, 5*time.Minute, eventuallyPollTime)

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

func TestStakeExpansionWithConsolidation(t *testing.T) {
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
	originalStakingAmount := int64(50000)
	expandedStakingAmount := int64(10000000000) // use a high value to ensure consolidation is needed

	// Create test data for original staking
	testStakingData := tm.getTestStakingData(t, tm.WalletPubKey, stakingTime, originalStakingAmount, 1)
	tm.createAndRegisterFinalityProviders(t, testStakingData)

	// Step 1: Create and activate initial BTC delegation
	originalTxHash := tm.sendStakingTxBTC(t, testStakingData)
	go tm.mineNEmptyBlocks(t, params.ConfirmationTimeBlocks, true)
	tm.waitForStakingTxState(t, originalTxHash, staker.BabylonPendingStatus)

	pend, err := tm.BabylonClient.QueryPendingBTCDelegations()
	require.NoError(t, err)
	require.Len(t, pend, 1)

	// Need to activate delegation before expansion
	tm.insertCovenantSigForDelegation(t, pend[0])
	tm.waitForStakingTxState(t, originalTxHash, staker.BabylonVerifiedStatus)

	require.Eventually(t, func() bool {
		txFromMempool := retrieveTransactionFromMempool(t, tm.TestRpcBtcClient, []*chainhash.Hash{originalTxHash})
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
		*originalTxHash,
		proof,
	)
	require.NoError(t, err)
	tm.waitForStakingTxState(t, originalTxHash, staker.BabylonActiveStatus)

	// Step 2: Try stake expansion without having a consolidated UTXO - this should fail with insufficient funds error
	fpKeys := make([]string, len(testStakingData.FinalityProviderBtcKeys))
	for i, fpKey := range testStakingData.FinalityProviderBtcKeys {
		fpKeys[i] = hex.EncodeToString(schnorr.SerializePubKey(fpKey))
	}

	// This should fail because the largest single UTXO is not enough for the expansion
	_, err = tm.StakerClient.StakeExpand(
		context.Background(),
		tm.MinerAddr.String(),
		expandedStakingAmount,
		fpKeys,
		int64(stakingTime),
		originalTxHash.String(),
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "insufficient funds") // Expected error message

	// Step 3: Try stake expansion with consolidation - this should succeed
	// Call the consolidation endpoint to consolidate the UTXOs
	consolidationResp, err := tm.StakerClient.ConsolidateUTXOs(
		context.Background(),
		tm.MinerAddr.String(),
		expandedStakingAmount,
	)
	require.NoError(t, err)

	// Wait for consolidation transaction to be confirmed
	consolidationTxHash, err := chainhash.NewHashFromStr(consolidationResp.TxHash)
	require.NoError(t, err)

	// Mine the consolidation transaction
	require.Eventually(t, func() bool {
		txFromMempool := retrieveTransactionFromMempool(t, tm.TestRpcBtcClient, []*chainhash.Hash{consolidationTxHash})
		return len(txFromMempool) == 1
	}, eventuallyWaitTimeOut, eventuallyPollTime)

	// report block to babylon
	mBlock = tm.mineBlock(t)
	_, err = tm.BabylonClient.InsertBtcBlockHeaders([]*wire.BlockHeader{&mBlock.Header})
	require.NoError(t, err)

	expansionResp, err := tm.StakerClient.StakeExpand(
		context.Background(),
		tm.MinerAddr.String(),
		expandedStakingAmount,
		fpKeys,
		int64(stakingTime),
		originalTxHash.String(),
	)
	require.NoError(t, err)

	expansionTxHash, err := chainhash.NewHashFromStr(expansionResp.TxHash)
	require.NoError(t, err)

	// Step 4: Verify new BTC delegation is pending
	tm.waitForStakingTxState(t, expansionTxHash, staker.BabylonPendingStatus)

	pendingDel, err := tm.BabylonClient.QueryPendingBTCDelegations()
	require.NoError(t, err)
	require.Len(t, pendingDel, 1)
	require.NotNil(t, pendingDel[0].StkExp)

	// Step 5: Covenant signatures for expansion
	tm.insertCovenantSigForDelegation(t, pendingDel[0])
	tm.waitForStakingTxState(t, expansionTxHash, staker.BabylonVerifiedStatus)

	// stake expansion delegation should be in verified state
	verifiedDel, err := tm.BabylonClient.QueryVerifiedBTCDelegations()
	require.NoError(t, err)
	require.Len(t, verifiedDel, 1)
	require.NotNil(t, verifiedDel[0].StkExp)

	// Step 6: Wait for expansion transaction to be submitted to Bitcoin mempool
	require.Eventually(t, func() bool {
		txFromMempool := retrieveTransactionFromMempool(t, tm.TestRpcBtcClient, []*chainhash.Hash{expansionTxHash})
		return len(txFromMempool) == 1
	}, eventuallyWaitTimeOut, eventuallyPollTime)

	// Step 7: Mine the expansion transaction
	expansionBlock := tm.mineBlock(t)
	require.Equal(t, 2, len(expansionBlock.Transactions))

	expansionHeaderBytes := bbntypes.NewBTCHeaderBytesFromBlockHeader(&expansionBlock.Header)
	expansionTxInclProof, err := btcctypes.SpvProofFromHeaderAndTransactions(&expansionHeaderBytes, txsToBytes(expansionBlock.Transactions), 1)
	require.NoError(t, err)

	_, err = tm.BabylonClient.InsertBtcBlockHeaders([]*wire.BlockHeader{&expansionBlock.Header})
	require.NoError(t, err)

	// Step 8: Wait for the expansion transaction to be k-deep on Bitcoin
	tm.mineNEmptyBlocks(t, staker.UnbondingTxConfirmations, true)
	require.Eventually(t, func() bool {
		// Get transaction details and verify confirmations
		res, err := tm.Sa.Wallet().TxVerbose(expansionTxHash)
		if err != nil {
			return false
		}
		// Check if we have the required number of confirmations
		return res.Confirmations >= staker.UnbondingTxConfirmations
	}, eventuallyWaitTimeOut, eventuallyPollTime)

	// Step 9: Report expansion transaction via MsgBTCUndelegate for the original delegation
	rawStkExpTransaction, err := tm.TestRpcBtcClient.GetRawTransaction(expansionTxHash)
	require.NoError(t, err)
	expansionMsgTx := rawStkExpTransaction.MsgTx()

	// get funding txs for the stake expansion
	var fundingTxs [][]byte
	for _, txIn := range expansionMsgTx.TxIn {
		rawTransaction, err := tm.TestRpcBtcClient.GetRawTransaction(&txIn.PreviousOutPoint.Hash)
		require.NoError(t, err)

		serializedTx, err := bbntypes.SerializeBTCTx(rawTransaction.MsgTx())
		require.NoError(t, err)

		fundingTxs = append(fundingTxs, serializedTx)
	}

	err = tm.BabylonClient.ReportUnbonding(
		*originalTxHash,
		expansionMsgTx,
		expansionTxInclProof,
		fundingTxs,
	)
	require.NoError(t, err)

	// Step 10: Wait for expansion to be active
	// Verify the original delegation is no longer active
	// and the expansion delegation is active
	tm.waitForStakingTxState(t, expansionTxHash, staker.BabylonActiveStatus)

	originalDelegation, err := tm.BabylonClient.QueryBTCDelegation(originalTxHash)
	require.NoError(t, err)
	require.False(t, originalDelegation.BtcDelegation.Active)

	expansionDelegation, err := tm.BabylonClient.QueryBTCDelegation(expansionTxHash)
	require.NoError(t, err)
	require.True(t, expansionDelegation.BtcDelegation.Active)
	require.NotNil(t, expansionDelegation.BtcDelegation.StkExp)

	// The expanded delegation should have the new amount
	require.Equal(t, uint64(expandedStakingAmount), expansionDelegation.BtcDelegation.TotalSat)
}

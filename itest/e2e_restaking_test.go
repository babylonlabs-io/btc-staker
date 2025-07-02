//go:build e2e
// +build e2e

package e2etest

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/babylonlabs-io/babylon/v3/testutil/datagen"
	bbntypes "github.com/babylonlabs-io/babylon/v3/types"
	btcctypes "github.com/babylonlabs-io/babylon/v3/x/btccheckpoint/types"
	bsctypes "github.com/babylonlabs-io/babylon/v3/x/btcstkconsumer/types"
	"github.com/babylonlabs-io/btc-staker/babylonclient"
	"github.com/babylonlabs-io/btc-staker/staker"
	"github.com/babylonlabs-io/btc-staker/walletcontroller"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sttypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/stretchr/testify/require"
)

type testStakingDataWithCZFPs struct {
	*testStakingData
	consumerRegister *bsctypes.ConsumerRegister
	CZFPBabylonSKs   []*secp256k1.PrivKey
	CZFPBabylonAddrs []sdk.AccAddress
	CZFPBTCSKs       []*btcec.PrivateKey
	CZFPBTCPKs       []*btcec.PublicKey
}

func (d *testStakingDataWithCZFPs) GetNumRestakedFPsInCZ() int {
	return len(d.CZFPBabylonSKs)
}

func (tm *TestManager) getTestStakingDataWithCZFPs(
	t *testing.T,
	stakerKey *btcec.PublicKey,
	stakingTime uint16,
	stakingAmount int64,
	numRestakedFPs int,
	numRestakedConsumerChainFPs int,
) *testStakingDataWithCZFPs {
	data := &testStakingDataWithCZFPs{}
	data.testStakingData = tm.getTestStakingData(t, stakerKey, stakingTime, stakingAmount, numRestakedFPs)

	fpBTCSKs, fpBTCPKs, err := datagen.GenRandomBTCKeyPairs(r, numRestakedConsumerChainFPs)
	require.NoError(t, err)

	fpBBNSKs := make([]*secp256k1.PrivKey, numRestakedConsumerChainFPs)
	fpBBNAddrs := make([]sdk.AccAddress, numRestakedConsumerChainFPs)
	for i := 0; i < numRestakedConsumerChainFPs; i++ {
		fpBBNSK := secp256k1.GenPrivKey()
		fpBBNSKs[i] = fpBBNSK
		fpAddr := sdk.AccAddress(fpBBNSK.PubKey().Address().Bytes())
		fpBBNAddrs[i] = fpAddr
	}

	data.CZFPBabylonSKs = fpBBNSKs
	data.CZFPBabylonAddrs = fpBBNAddrs
	data.CZFPBTCSKs = fpBTCSKs
	data.CZFPBTCPKs = fpBTCPKs
	data.consumerRegister = datagen.GenRandomCosmosConsumerRegister(r)
	data.consumerRegister.ConsumerId = "09-localhost" // TODO: mock a real consumer ID

	return data
}

func (tm *TestManager) createAndRegisterFinalityProvidersWithCZ(
	t *testing.T,
	data *testStakingDataWithCZFPs,
) {
	// register chain
	_, err := tm.BabylonClient.RegisterConsumerChain(data.consumerRegister.ConsumerId, data.consumerRegister.ConsumerName, data.consumerRegister.ConsumerDescription)
	require.NoError(t, err)

	// top up the addresses with some BBN
	strAddrs := make([]string, len(data.CZFPBabylonAddrs))
	for i, addr := range data.CZFPBabylonAddrs {
		strAddrs[i] = addr.String()
	}
	_, _, err = tm.manager.BabylondTxBankMultiSend(t, "node0", "1000000ubbn", strAddrs...)
	require.NoError(t, err)

	// create and register finality providers for consumer chains
	for i := 0; i < data.GetNumRestakedFPsInCZ(); i++ {
		// ensure the finality provider in data does not exist yet
		fpResp, err := tm.BabylonClient.QueryFinalityProvider(data.CZFPBTCPKs[i])
		require.Nil(t, fpResp)
		require.Error(t, err)
		require.True(t, errors.Is(err, babylonclient.ErrFinalityProviderDoesNotExist))

		pop, err := datagen.NewPoPBTC("", data.CZFPBabylonAddrs[i], data.CZFPBTCSKs[i])
		require.NoError(t, err)

		fpPK := data.CZFPBTCPKs[i]
		fpBTCPK := bbntypes.NewBIP340PubKeyFromBTCPK(fpPK)

		params, err := tm.BabylonClient.QueryStakingTracker()
		require.NoError(t, err)

		// register the generated finality provider
		err = tm.BabylonClient.RegisterFinalityProvider(
			data.CZFPBabylonAddrs[i],
			data.CZFPBabylonSKs[i],
			fpBTCPK,
			&params.MinComissionRate,
			&sttypes.Description{
				Moniker: "tester",
			},
			pop,
			data.consumerRegister.ConsumerId,
		)
		require.NoError(t, err)

		// ensure the finality provider has been registered
		var fp *babylonclient.FinalityProviderClientResponse
		require.Eventually(t, func() bool {
			fp, err = tm.BabylonClient.QueryFinalityProvider(fpPK)
			return err == nil && fp != nil
		}, eventuallyWaitTimeOut, eventuallyPollTime)

		require.Equal(t, bbntypes.NewBIP340PubKeyFromBTCPK(&fp.FinalityProvider.BtcPk), fpBTCPK)
	}

	// create and register finality providers for Babylon
	tm.createAndRegisterFinalityProviders(t, data.testStakingData)
}

func (tm *TestManager) sendStakingTxWithCZFPs(t *testing.T, data *testStakingDataWithCZFPs) *chainhash.Hash {
	fpBTCPKs := []string{}
	// Babylon FP PKs
	for i := 0; i < data.GetNumRestakedFPs(); i++ {
		fpBTCPK := hex.EncodeToString(schnorr.SerializePubKey(data.testStakingData.FinalityProviderBtcKeys[i]))
		fpBTCPKs = append(fpBTCPKs, fpBTCPK)
	}
	// consumer chain FP PKs
	for i := 0; i < data.GetNumRestakedFPsInCZ(); i++ {
		fpBTCPK := hex.EncodeToString(schnorr.SerializePubKey(data.CZFPBTCPKs[i]))
		fpBTCPKs = append(fpBTCPKs, fpBTCPK)
	}
	// restake
	res, err := tm.StakerClient.Stake(
		context.Background(),
		tm.MinerAddr.String(),
		data.StakingAmount,
		fpBTCPKs,
		int64(data.StakingTime),
	)
	require.NoError(t, err)
	txHash := res.TxHash

	hashFromString, err := chainhash.NewHashFromStr(txHash)
	require.NoError(t, err)

	return hashFromString
}

func TestRestakingToConsumerChains(t *testing.T) {
	// TODO: fix this test, it requires deploying wasm smart contract to work
	t.Skip("Skipping restaking to consumer chains test, it's not working. Fix it!")

	// need to have at least 300 block on testnet as only then segwit is activated.
	// Mature output is out which has 100 confirmations, which means 200mature outputs
	// will generate 300 blocks
	t.Parallel()
	numMatureOutputs := uint32(200)
	ctx, cancel := context.WithCancel(context.Background())
	tm := StartManager(t, ctx, numMatureOutputs)
	defer tm.Stop(t, cancel)
	tm.insertAllMinedBlocksToBabylon(t)

	cl := tm.Sa.BabylonController()
	params, err := cl.Params()
	require.NoError(t, err)
	stakingTime := uint16(1000)

	// restaked to 2 Babylon finality providers and 3 CZ finality providers
	data := tm.getTestStakingDataWithCZFPs(t, tm.WalletPubKey, stakingTime, 50000, 2, 3)

	hashed, err := chainhash.NewHash(datagen.GenRandomByteArray(r, 32))
	require.NoError(t, err)
	scr, err := txscript.PayToTaprootScript(tm.CovenantPrivKeys[0].PubKey())
	require.NoError(t, err)
	_, st, erro := tm.Sa.Wallet().TxDetails(hashed, scr)
	// query for existing tx is not an error, proper state should be returned
	require.NoError(t, erro)
	require.Equal(t, st, walletcontroller.TxNotFound)

	tm.createAndRegisterFinalityProvidersWithCZ(t, data)

	txHash := tm.sendStakingTxWithCZFPs(t, data)
	go tm.mineNEmptyBlocks(t, 6, true)
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
}

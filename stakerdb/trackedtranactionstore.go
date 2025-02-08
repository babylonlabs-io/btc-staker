package stakerdb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"

	"github.com/babylonlabs-io/btc-staker/proto"
	"github.com/babylonlabs-io/btc-staker/utils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/walletdb"
	pm "google.golang.org/protobuf/proto"

	"github.com/lightningnetwork/lnd/kvdb"
)

var (
	// mapping uint64 -> proto.TrackedTransaction
	transactionBucketName = []byte("transactions")

	// mapping txHash -> uint64
	transactionIndexName = []byte("transactionIdx")

	// mapping outpoint -> txHash
	// It holds mapping from outpoint to transaction hash
	// outpoint: outpoint.txHash || bigendian(outpoint.index)
	inputsDataBucketName = []byte("inputs")

	// key for next transaction
	numTxKey = []byte("ntk")
)

// StoredTransaction is a struct which stores information about transactions
type StoredTransaction struct {
	StoredTransactionIdx      uint64
	StakingTx                 *wire.MsgTx
	StakingOutputIndex        uint32
	StakingTxConfirmationInfo *BtcConfirmationInfo
	StakingTime               uint16
	FinalityProvidersBtcPks   []*btcec.PublicKey
	Pop                       *ProofOfPossession
	// Returning address as string, to avoid having to know how to decode address
	// which requires knowing the network we are on
	StakerAddress              string
	State                      proto.TransactionState // TODO: removed after bitcoin status can be obtained directly.
	UnbondingTxData            *UnbondingStoreData
	BabylonBTCDelegationTxHash string
}

// TrackedTransactionStore is a store for tracking transactions
type TrackedTransactionStore struct {
	db kvdb.Backend
}

// inputData is a struct which stores information about inputs
type inputData struct {
	inputs [][]byte
	txHash []byte
}

// StoredTransactionScanFn is a function which is called for each transaction
type StoredTransactionScanFn func(tx *StoredTransaction) error

// NewTrackedTransactionStore returns a new store backed by db
func NewTrackedTransactionStore(db kvdb.Backend) (*TrackedTransactionStore, error) {
	store := &TrackedTransactionStore{db}
	if err := store.initBuckets(); err != nil {
		return nil, fmt.Errorf("failed to initialize buckets: %w", err)
	}

	return store, nil
}

// initBuckets creates the necessary buckets in the backend db
func (c *TrackedTransactionStore) initBuckets() error {
	return kvdb.Batch(c.db, func(tx kvdb.RwTx) error {
		_, err := tx.CreateTopLevelBucket(transactionBucketName)
		if err != nil {
			return fmt.Errorf("failed to create transaction bucket: %w", err)
		}

		_, err = tx.CreateTopLevelBucket(transactionIndexName)
		if err != nil {
			return fmt.Errorf("failed to create transaction index bucket: %w", err)
		}

		_, err = tx.CreateTopLevelBucket(inputsDataBucketName)
		if err != nil {
			return fmt.Errorf("failed to create inputs data bucket: %w", err)
		}
		return nil
	})
}

// CreateTrackedTransaction creates a new tracked transaction
func CreateTrackedTransaction(
	btcTx *wire.MsgTx,
	stakingOutputIndex uint32,
	stakingTime uint16,
	fpPubKeys []*btcec.PublicKey,
	pop *ProofOfPossession,
	stakerAddress btcutil.Address,
) (*StoredTransaction, error) {
	serializedTx, err := utils.SerializeBtcTransaction(btcTx)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Bitcoin transaction: %w", err)
	}

	if len(fpPubKeys) == 0 {
		return nil, fmt.Errorf("cannot add transaction without finality providers public keys")
	}

	fpPubKeysBytes := make([][]byte, len(fpPubKeys))

	for i, pk := range fpPubKeys {
		fpPubKeysBytes[i] = schnorr.SerializePubKey(pk)
	}

	if pop == nil {
		return nil, fmt.Errorf("cannot add transaction without proof of possession")
	}

	msg := proto.TrackedTransaction{
		// Setting it to 0, proper number will be filled by `addTransactionInternal`
		TrackedTransactionIdx:        0,
		StakingTransaction:           serializedTx,
		StakingOutputIdx:             stakingOutputIndex,
		StakerAddress:                stakerAddress.EncodeAddress(),
		StakingTime:                  uint32(stakingTime),
		FinalityProvidersBtcPks:      fpPubKeysBytes,
		StakingTxBtcConfirmationInfo: nil,
		BtcSigType:                   pop.BtcSigType,
		BtcSigOverBbnStakerAddr:      pop.BtcSigOverBabylonAddr,
		UnbondingTxData:              nil,
	}

	return protoTxToStoredTransaction(&msg)
}

// AddNewStoredTransaction adds a new transaction to the store,
// sent to the Babylon chain.
func (c *TrackedTransactionStore) AddNewStoredTransaction(
	btcTx *wire.MsgTx,
	stakingOutputIndex uint32,
	stakingTime uint16,
	fpPubKeys []*btcec.PublicKey,
	pop *ProofOfPossession,
	stakerAddress btcutil.Address,
	unbondingTx *wire.MsgTx,
	unbondingTime uint16,
	btcDelTxHash string,
) error {
	txHash := btcTx.TxHash()

	txHashBytes := txHash[:]
	serializedTx, err := utils.SerializeBtcTransaction(btcTx)
	if err != nil {
		return fmt.Errorf("failed to serialize Bitcoin transaction: %w", err)
	}

	if len(fpPubKeys) == 0 {
		return fmt.Errorf("cannot add transaction without finality providers public keys")
	}

	fpPubKeysBytes := make([][]byte, len(fpPubKeys))
	for i, pk := range fpPubKeys {
		fpPubKeysBytes[i] = schnorr.SerializePubKey(pk)
	}

	if pop == nil {
		return fmt.Errorf("cannot add transaction without proof of possession")
	}

	update, err := newInitialUnbondingTxData(unbondingTx, unbondingTime)
	if err != nil {
		return fmt.Errorf("failed to create unbonding transaction data: %w", err)
	}

	msg := proto.TrackedTransaction{
		// Setting it to 0, proper number will be filled by `addTransactionInternal`
		TrackedTransactionIdx:        0,
		StakingTransaction:           serializedTx,
		StakingOutputIdx:             stakingOutputIndex,
		StakerAddress:                stakerAddress.EncodeAddress(),
		StakingTime:                  uint32(stakingTime),
		FinalityProvidersBtcPks:      fpPubKeysBytes,
		StakingTxBtcConfirmationInfo: nil,
		BtcSigType:                   pop.BtcSigType,
		BtcSigOverBbnStakerAddr:      pop.BtcSigOverBabylonAddr,
		UnbondingTxData:              update,
		BabylonBTCDelegationTxHash:   btcDelTxHash,
	}

	inputData, err := getInputData(btcTx)
	if err != nil {
		return fmt.Errorf("failed to get input data: %w", err)
	}

	return c.addTransactionInternal(
		txHashBytes, &msg, inputData,
	)
}

// SetTxConfirmed sets the confirmation info.
// After program is modified to get btc state directly, this function would be removed.
func (c *TrackedTransactionStore) SetTxConfirmed(
	txHash *chainhash.Hash,
	blockHash *chainhash.Hash,
	blockHeight uint32,
) error {
	setTxConfirmed := func(tx *proto.TrackedTransaction) error {
		tx.StakingTxBtcConfirmationInfo = &proto.BTCConfirmationInfo{
			BlockHash:   blockHash.CloneBytes(),
			BlockHeight: blockHeight,
		}
		return nil
	}

	return c.setTxState(txHash, setTxConfirmed)
}

// SetTxUnbondingSignaturesReceived sets covenant signatures to received value
// It set state to VERIFIED before, but not current version,
// since state can be obtained by babylon node directly.
// After program is modified to get btc state directly, this function would be removed.
func (c *TrackedTransactionStore) SetTxUnbondingSignaturesReceived(
	txHash *chainhash.Hash,
	covenantSignatures []PubKeySigPair,
) error {
	setUnbondingSignaturesReceived := func(tx *proto.TrackedTransaction) error {
		if tx.UnbondingTxData == nil {
			return fmt.Errorf("cannot set unbonding signatures received, because unbonding tx data does not exist: %w", ErrUnbondingDataNotFound)
		}

		if len(tx.UnbondingTxData.CovenantSignatures) > 0 {
			return fmt.Errorf("cannot set unbonding signatures received, because unbonding signatures already exist: %w", ErrInvalidUnbondingDataUpdate)
		}
		tx.UnbondingTxData.CovenantSignatures = covenantSigsToProto(covenantSignatures)
		return nil
	}
	return c.setTxState(txHash, setUnbondingSignaturesReceived)
}

// SetTxUnbondingConfirmedOnBtc sets the state to UNBONDING_CONFIRMED_ON_BTC
// and the confirmation info.
// After program is modified to get btc state directly, this function would be removed.
// TODO: UNBONDING_CONFIRMED_ON_BTC is used in e2e test to check if the state is set correctly -> should be removed later.
func (c *TrackedTransactionStore) SetTxUnbondingConfirmedOnBtc(
	txHash *chainhash.Hash,
	blockHash *chainhash.Hash,
	blockHeight uint32,
) error {
	setUnbondingConfirmedOnBtc := func(tx *proto.TrackedTransaction) error {
		if tx.UnbondingTxData == nil {
			return fmt.Errorf("cannot set unbonding confirmed on btc, because unbonding tx data does not exist: %w", ErrUnbondingDataNotFound)
		}

		tx.State = proto.TransactionState_UNBONDING_CONFIRMED_ON_BTC
		tx.UnbondingTxData.UnbondingTxBtcConfirmationInfo = &proto.BTCConfirmationInfo{
			BlockHash:   blockHash.CloneBytes(),
			BlockHeight: blockHeight,
		}
		return nil
	}

	return c.setTxState(txHash, setUnbondingConfirmedOnBtc)
}

// SetTxSpentOnBtc sets the state to SPENT_ON_BTC
// After program is modified to get btc state directly, this function would be removed.
// TODO: check this function is necessary.
func (c *TrackedTransactionStore) SetTxSpentOnBtc(txHash *chainhash.Hash) error {
	setTxSpentOnBtc := func(tx *proto.TrackedTransaction) error {
		tx.State = proto.TransactionState_SPENT_ON_BTC
		return nil
	}

	return c.setTxState(txHash, setTxSpentOnBtc)
}

// protoTxToStoredTransaction converts a protobuf TrackedTransaction to StoredTransaction
func protoTxToStoredTransaction(ttx *proto.TrackedTransaction) (*StoredTransaction, error) {
	var stakingTx wire.MsgTx

	if err := stakingTx.Deserialize(bytes.NewReader(ttx.StakingTransaction)); err != nil {
		return nil, fmt.Errorf("failed to deserialize staking transaction <%s>: %w", stakingTx.TxHash().String(), err)
	}

	var utd *UnbondingStoreData
	if ttx.UnbondingTxData != nil {
		unbondingData, err := protoUnbondingDataToUnbondingStoreData(ttx.UnbondingTxData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse unbonding data: %w", err)
		}
		utd = unbondingData
	}

	stakingTxConfgInfo, err := protoBtcConfirmationInfoToBtcConfirmationInfo(ttx.StakingTxBtcConfirmationInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to parse staking tx confirmation info: %w", err)
	}

	if ttx.StakingTime > math.MaxUint16 {
		return nil, fmt.Errorf("staking time is too large. Max value is %d", math.MaxUint16)
	}

	fpPubkeys := make([]*btcec.PublicKey, len(ttx.FinalityProvidersBtcPks))
	for i, pk := range ttx.FinalityProvidersBtcPks {
		fpPubkeys[i], err = schnorr.ParsePubKey(pk)
		if err != nil {
			return nil, fmt.Errorf("failed to parse finality provider public key: %w", err)
		}
	}

	return &StoredTransaction{
		StoredTransactionIdx:      ttx.TrackedTransactionIdx,
		StakingTx:                 &stakingTx,
		StakingOutputIndex:        ttx.StakingOutputIdx,
		StakingTxConfirmationInfo: stakingTxConfgInfo,
		StakingTime:               uint16(ttx.StakingTime),
		FinalityProvidersBtcPks:   fpPubkeys,
		Pop: &ProofOfPossession{
			BtcSigType:            ttx.BtcSigType,
			BtcSigOverBabylonAddr: ttx.BtcSigOverBbnStakerAddr,
		},
		StakerAddress:              ttx.StakerAddress,
		State:                      ttx.State,
		UnbondingTxData:            utd,
		BabylonBTCDelegationTxHash: ttx.BabylonBTCDelegationTxHash,
	}, nil
}

// protoUnbondingDataToUnbondingStoreData converts a protobuf UnbondingTxData to UnbondingStoreData
func protoUnbondingDataToUnbondingStoreData(ud *proto.UnbondingTxData) (*UnbondingStoreData, error) {
	// Unbodning txdata should always contains unbonding tx
	var unbondingTx wire.MsgTx
	if err := unbondingTx.Deserialize(bytes.NewReader(ud.UnbondingTransaction)); err != nil {
		return nil, fmt.Errorf("failed to deserialize unbonding transaction: %w", err)
	}

	if ud.UnbondingTime > math.MaxUint16 {
		return nil, fmt.Errorf("unbonding time is too large. Max value is %d", math.MaxUint16)
	}

	var sigs []PubKeySigPair
	for _, sig := range ud.CovenantSignatures {
		covenantSig, err := covenantSigFromProto(sig)
		if err != nil {
			return nil, fmt.Errorf("failed to parse covenant signature: %w", err)
		}
		sigs = append(sigs, *covenantSig)
	}

	unbondingTxConfirmationInfo, err := protoBtcConfirmationInfoToBtcConfirmationInfo(ud.UnbondingTxBtcConfirmationInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to parse unbonding tx confirmation info: %w", err)
	}

	return &UnbondingStoreData{
		UnbondingTx:                 &unbondingTx,
		UnbondingTime:               uint16(ud.UnbondingTime),
		CovenantSignatures:          sigs,
		UnbondingTxConfirmationInfo: unbondingTxConfirmationInfo,
	}, nil
}

// protoBtcConfirmationInfoToBtcConfirmationInfo converts a protobuf BTCConfirmationInfo to BtcConfirmationInfo
func protoBtcConfirmationInfoToBtcConfirmationInfo(ci *proto.BTCConfirmationInfo) (*BtcConfirmationInfo, error) {
	if ci == nil {
		return nil, nil
	}

	hash, err := chainhash.NewHash(ci.BlockHash)
	if err != nil {
		return nil, fmt.Errorf("failed to parse block hash: %w", err)
	}

	return &BtcConfirmationInfo{
		Height:    ci.BlockHeight,
		BlockHash: *hash,
	}, nil
}

// addTransactionInternal adds a new transaction to the store
func (c *TrackedTransactionStore) addTransactionInternal(txHashBytes []byte, tt *proto.TrackedTransaction, id *inputData) error {
	return kvdb.Batch(c.db, func(tx kvdb.RwTx) error {
		transactionsBucketIdxBucket := tx.ReadWriteBucket(transactionIndexName)
		if transactionsBucketIdxBucket == nil {
			return ErrCorruptedTransactionsDB
		}

		// check index first to avoid duplicates
		maybeTx := transactionsBucketIdxBucket.Get(txHashBytes)
		if maybeTx != nil {
			return ErrDuplicateTransaction
		}

		transactionsBucket := tx.ReadWriteBucket(transactionBucketName)
		if transactionsBucket == nil {
			return ErrCorruptedTransactionsDB
		}

		return saveTrackedTransaction(tx, transactionsBucketIdxBucket, transactionsBucket, txHashBytes, tt, id)
	})
}

// saveTrackedTransaction adds a new transaction to the store
func saveTrackedTransaction(
	rwTx kvdb.RwTx,
	txIdxBucket walletdb.ReadWriteBucket,
	txBucket walletdb.ReadWriteBucket,
	txHashBytes []byte,
	tx *proto.TrackedTransaction,
	id *inputData,
) error {
	if tx == nil {
		return fmt.Errorf("cannot save nil tracked transactions")
	}

	nextTxKey := nextTxKey(txIdxBucket)
	tx.TrackedTransactionIdx = nextTxKey

	marshalled, err := pm.Marshal(tx)
	if err != nil {
		return fmt.Errorf("failed to marshal tracked transaction: %w", err)
	}

	nextTxKeyBytes := uint64KeyToBytes(nextTxKey)

	if err := txBucket.Put(nextTxKeyBytes, marshalled); err != nil {
		return fmt.Errorf("failed to save tracked transaction with next transaction key: %w", err)
	}

	if err := txIdxBucket.Put(txHashBytes, nextTxKeyBytes); err != nil {
		return fmt.Errorf("failed to save tracked transaction with tx hash: %w", err)
	}

	if id != nil {
		inputDataBucket := rwTx.ReadWriteBucket(inputsDataBucketName)
		if inputDataBucket == nil {
			return ErrCorruptedTransactionsDB
		}

		for _, input := range id.inputs {
			// save all the inputs to the transaction
			if err := inputDataBucket.Put(input, txHashBytes); err != nil {
				return fmt.Errorf("failed to save input data: %w", err)
			}
		}
	}

	// increment counter for the next transaction
	return txIdxBucket.Put(numTxKey, uint64KeyToBytes(nextTxKey+1))
}

// nextTxKey returns the next transaction key
func nextTxKey(txIdxBucket walletdb.ReadBucket) uint64 {
	numTxBytes := txIdxBucket.Get(numTxKey)
	var currKey uint64
	if numTxBytes == nil {
		currKey = 1
	} else {
		currKey = binary.BigEndian.Uint64(numTxBytes)
	}

	return currKey
}

// uint64KeyToBytes converts uint64 to bytes
func uint64KeyToBytes(key uint64) []byte {
	var keyBytes = make([]byte, 8)
	binary.BigEndian.PutUint64(keyBytes, key)
	return keyBytes
}

// setTxState updates state of the transaction
func (c *TrackedTransactionStore) setTxState(
	txHash *chainhash.Hash,
	stateTransitionFn func(*proto.TrackedTransaction) error,
) error {
	txHashBytes := txHash.CloneBytes()

	return kvdb.Batch(c.db, func(tx kvdb.RwTx) error {
		transactionIdxBucket := tx.ReadWriteBucket(transactionIndexName)

		if transactionIdxBucket == nil {
			return ErrCorruptedTransactionsDB
		}

		transactionsBucket := tx.ReadWriteBucket(transactionBucketName)
		if transactionsBucket == nil {
			return ErrCorruptedTransactionsDB
		}

		maybeTx, txKey, err := getTxByHash(txHashBytes, transactionIdxBucket, transactionsBucket)
		if err != nil {
			return fmt.Errorf("failed to get transaction by hash: %w", err)
		}

		var storedTx proto.TrackedTransaction
		err = pm.Unmarshal(maybeTx, &storedTx)
		if err != nil {
			return ErrCorruptedTransactionsDB
		}

		if err := stateTransitionFn(&storedTx); err != nil {
			return fmt.Errorf("failed to set state: %w", err)
		}

		marshalled, err := pm.Marshal(&storedTx)
		if err != nil {
			return fmt.Errorf("failed to marshal transaction: %w", err)
		}

		if err := transactionsBucket.Put(txKey, marshalled); err != nil {
			return fmt.Errorf("failed to save transaction: %w", err)
		}

		// delegation has been activaten remove used inputs if any exists
		// TODO(konrad): This is not pretty architecture wise and a bit broken in scenario
		// that delegation is never activated
		if storedTx.State == proto.TransactionState_DELEGATION_ACTIVE {
			inputDataBucket := tx.ReadWriteBucket(inputsDataBucketName)
			if inputDataBucket == nil {
				return ErrCorruptedTransactionsDB
			}

			var stakingTx wire.MsgTx
			if err := stakingTx.Deserialize(bytes.NewReader(storedTx.StakingTransaction)); err != nil {
				return fmt.Errorf("failed to deserialize staking transaction: %w", err)
			}

			for _, input := range stakingTx.TxIn {
				input, err := outpointBytes(&input.PreviousOutPoint)
				if err != nil {
					return fmt.Errorf("failed to convert outpoint: %w", err)
				}

				// if key does not exist, this operation is no-op
				if err := inputDataBucket.Delete(input); err != nil {
					return fmt.Errorf("failed to delete input: %w", err)
				}
			}
		}
		return nil
	})
}

// QueryStoredTransactions queries stored transactions in the database
func (c *TrackedTransactionStore) QueryStoredTransactions(q StoredTransactionQuery) (StoredTransactionQueryResult, error) {
	var resp StoredTransactionQueryResult

	if err := c.db.View(func(tx kvdb.RTx) error {
		transactionsBucket := tx.ReadBucket(transactionBucketName)
		if transactionsBucket == nil {
			return ErrCorruptedTransactionsDB
		}

		transactionIdxBucket := tx.ReadBucket(transactionIndexName)
		if transactionIdxBucket == nil {
			return ErrCorruptedTransactionsDB
		}

		numTransactions := getNumTx(transactionIdxBucket)
		if numTransactions == 0 {
			return nil
		}

		resp.Total = numTransactions
		paginator := newPaginator(
			transactionsBucket.ReadCursor(), q.Reversed, q.IndexOffset,
			q.NumMaxTransactions,
		)

		accumulateTransactions := func(_, transaction []byte) (bool, error) {
			protoTx := proto.TrackedTransaction{}
			if err := pm.Unmarshal(transaction, &protoTx); err != nil {
				return false, fmt.Errorf("failed to unmarshal transaction: %w", err)
			}

			txFromDB, err := protoTxToStoredTransaction(&protoTx)
			if err != nil {
				return false, fmt.Errorf("failed to convert proto transaction to stored transaction: %w", err)
			}

			// we have query only for withdrawable transaction i.e transactions which
			// either in SENT_TO_BABYLON or DELEGATION_ACTIVE or UNBONDING_CONFIRMED_ON_BTC state and which timelock has expired
			if q.withdrawableTransactionsFilter != nil {
				var confirmationHeight uint32
				var scriptTimeLock uint16

				switch {
				case txFromDB.StakingTxConfirmedOnBtc() && !txFromDB.UnbondingTxConfirmedOnBtc():
					scriptTimeLock = txFromDB.StakingTime
					confirmationHeight = txFromDB.StakingTxConfirmationInfo.Height
				case txFromDB.StakingTxConfirmedOnBtc() && txFromDB.UnbondingTxConfirmedOnBtc():
					scriptTimeLock = txFromDB.UnbondingTxData.UnbondingTime
					confirmationHeight = txFromDB.UnbondingTxData.UnbondingTxConfirmationInfo.Height
				default:
					return false, nil
				}

				timeLockExpired := isTimeLockExpired(
					confirmationHeight,
					scriptTimeLock,
					q.withdrawableTransactionsFilter.currentBestBlockHeight,
				)

				if timeLockExpired {
					resp.Transactions = append(resp.Transactions, *txFromDB)
					return true, nil
				}

				return false, nil
			}
			resp.Transactions = append(resp.Transactions, *txFromDB)
			return true, nil
		}

		if err := paginator.query(accumulateTransactions); err != nil {
			return fmt.Errorf("failed to query paginator: %w", err)
		}

		if q.Reversed {
			numTx := len(resp.Transactions)
			for i := 0; i < numTx/2; i++ {
				reverse := numTx - i - 1
				resp.Transactions[i], resp.Transactions[reverse] =
					resp.Transactions[reverse], resp.Transactions[i]
			}
		}

		return nil
	}, func() {
		resp = StoredTransactionQueryResult{}
	}); err != nil {
		return resp, fmt.Errorf("failed to query stored transactions: %w", err)
	}

	return resp, nil
}

// getNumTx returns the number of transactions in the transaction index bucket
func getNumTx(txIdxBucket walletdb.ReadBucket) uint64 {
	// we are starting indexing transactions from 1, and nextTxKey always return next key
	// which should be used when indexing transaction, so to get number of transactions
	// we need to subtract 1
	return nextTxKey(txIdxBucket) - 1
}

// QueryAllStoredTransactions queries all stored transactions in the database.
func (c *TrackedTransactionStore) QueryAllStoredTransactions() ([]StoredTransaction, error) {
	q := DefaultStoredTransactionQuery()
	// MaxUint64 indicates we will scan over all transactions
	q.NumMaxTransactions = math.MaxUint64

	resp, err := c.QueryStoredTransactions(q)
	if err != nil {
		return nil, fmt.Errorf("failed to query stored transactions: %w", err)
	}

	return resp.Transactions, nil
}

// DefaultStoredTransactionQuery returns a default stored transaction query
func DefaultStoredTransactionQuery() StoredTransactionQuery {
	return StoredTransactionQuery{
		IndexOffset:                    0,
		NumMaxTransactions:             50,
		Reversed:                       false,
		withdrawableTransactionsFilter: nil,
	}
}

// ScanTrackedTransactions scans the transactions bucket and calls the scan function
// for each transaction.
func (c *TrackedTransactionStore) ScanTrackedTransactions(scanFunc StoredTransactionScanFn, reset func()) error {
	return kvdb.View(c.db, func(tx kvdb.RTx) error {
		transactionsBucket := tx.ReadBucket(transactionBucketName)

		if transactionsBucket == nil {
			return ErrCorruptedTransactionsDB
		}

		return transactionsBucket.ForEach(func(_, v []byte) error {
			var storedTxProto proto.TrackedTransaction
			if err := pm.Unmarshal(v, &storedTxProto); err != nil {
				return ErrCorruptedTransactionsDB
			}

			txFromDB, err := protoTxToStoredTransaction(&storedTxProto)
			if err != nil {
				return fmt.Errorf("failed to convert proto transaction to stored transaction: %w", err)
			}

			return scanFunc(txFromDB)
		})
	}, reset)
}

// GetTransaction returns the transaction by hash
func (c *TrackedTransactionStore) GetTransaction(txHash *chainhash.Hash) (*StoredTransaction, error) {
	var storedTx *StoredTransaction
	txHashBytes := txHash.CloneBytes()

	if err := c.db.View(func(tx kvdb.RTx) error {
		transactionIdxBucket := tx.ReadBucket(transactionIndexName)

		if transactionIdxBucket == nil {
			return ErrCorruptedTransactionsDB
		}

		transactionsBucket := tx.ReadBucket(transactionBucketName)
		if transactionsBucket == nil {
			return ErrCorruptedTransactionsDB
		}

		maybeTx, _, err := getTxByHash(txHashBytes, transactionIdxBucket, transactionsBucket)
		if err != nil {
			return fmt.Errorf("failed to get transaction by hash: %w", err)
		}

		var storedTxProto proto.TrackedTransaction
		if err := pm.Unmarshal(maybeTx, &storedTxProto); err != nil {
			return ErrCorruptedTransactionsDB
		}

		txFromDB, err := protoTxToStoredTransaction(&storedTxProto)
		if err != nil {
			return fmt.Errorf("failed to convert proto transaction to stored transaction: %w", err)
		}

		storedTx = txFromDB
		return nil
	}, func() {}); err != nil {
		return nil, fmt.Errorf("failed to get transaction by hash: %w", err)
	}

	return storedTx, nil
}

// getTxByHash retruns transaction and transaction key if transaction with given hash exsits
func getTxByHash(
	txHashBytes []byte,
	txIndexBucket walletdb.ReadBucket,
	txBucket walletdb.ReadBucket) ([]byte, []byte, error) {
	txKey := txIndexBucket.Get(txHashBytes)

	if txKey == nil {
		return nil, nil, ErrTransactionNotFound
	}

	maybeTx := txBucket.Get(txKey)
	if maybeTx == nil {
		// if we have index, but do not have transaction, it means something weird happened
		// and we have corrupted db
		return nil, nil, ErrCorruptedTransactionsDB
	}

	return maybeTx, txKey, nil
}

// StakingTxConfirmedOnBtc returns true only if staking transaction was sent and confirmed on bitcoin
func (t *StoredTransaction) StakingTxConfirmedOnBtc() bool {
	return t.StakingTxConfirmationInfo != nil
}

// UnbondingTxConfirmedOnBtc returns true only if unbonding transaction was sent and confirmed on bitcoin
func (t *StoredTransaction) UnbondingTxConfirmedOnBtc() bool {
	if t.UnbondingTxData == nil {
		return false
	}
	return t.UnbondingTxData.UnbondingTxConfirmationInfo != nil
}

// --------------------------------------------------------------

// PubKeySigPair is a pair of a signature and a public key
type PubKeySigPair struct {
	Signature *schnorr.Signature
	PubKey    *btcec.PublicKey
}

// NewCovenantMemberSignature creates a new covenant member signature
func NewCovenantMemberSignature(
	sig *schnorr.Signature,
	pubKey *btcec.PublicKey,
) PubKeySigPair {
	return PubKeySigPair{
		sig,
		pubKey,
	}
}

// covenantSigToProto converts a covenant signature to a proto covenant signature
func covenantSigToProto(c *PubKeySigPair) *proto.CovenantSig {
	return &proto.CovenantSig{
		CovenantSig:      c.Signature.Serialize(),
		CovenantSigBtcPk: schnorr.SerializePubKey(c.PubKey),
	}
}

// covenantSigsToProto converts a slice of covenant signatures to a slice of proto covenant signatures
func covenantSigsToProto(c []PubKeySigPair) []*proto.CovenantSig {
	protoC := make([]*proto.CovenantSig, len(c))

	for i, sig := range c {
		protoC[i] = covenantSigToProto(&sig)
	}

	return protoC
}

// covenantSigFromProto converts a proto covenant signature to a covenant signature
func covenantSigFromProto(c *proto.CovenantSig) (*PubKeySigPair, error) {
	sig, err := schnorr.ParseSignature(c.CovenantSig)

	if err != nil {
		return nil, fmt.Errorf("failed to parse covenant signature: %w", err)
	}

	pubKey, err := schnorr.ParsePubKey(c.CovenantSigBtcPk)
	if err != nil {
		return nil, fmt.Errorf("failed to parse covenant public key: %w", err)
	}

	return &PubKeySigPair{
		Signature: sig,
		PubKey:    pubKey,
	}, nil
}

// --------------------------------------------------------------

// ProofOfPossession represents a proof of possession
type ProofOfPossession struct {
	BtcSigType            uint32
	BtcSigOverBabylonAddr []byte
}

// NewProofOfPossession creates a new ProofOfPossession
func NewProofOfPossession(
	btcSchnorrSigOverBabylonAddr []byte,
) *ProofOfPossession {
	return &ProofOfPossession{
		BtcSigOverBabylonAddr: btcSchnorrSigOverBabylonAddr,
	}
}

type BtcConfirmationInfo struct {
	Height    uint32
	BlockHash chainhash.Hash
}

type UnbondingStoreData struct {
	UnbondingTx                 *wire.MsgTx
	UnbondingTime               uint16
	CovenantSignatures          []PubKeySigPair
	UnbondingTxConfirmationInfo *BtcConfirmationInfo
}

func newInitialUnbondingTxData(
	unbondingTx *wire.MsgTx,
	unbondingTime uint16,
) (*proto.UnbondingTxData, error) {
	if unbondingTx == nil {
		return nil, fmt.Errorf("cannot create unbonding tx data without unbonding tx")
	}

	serializedTx, err := utils.SerializeBtcTransaction(unbondingTx)

	if err != nil {
		return nil, fmt.Errorf("cannot create unbonding tx data: %w", err)
	}

	unbondingData := &proto.UnbondingTxData{
		UnbondingTransaction:           serializedTx,
		UnbondingTime:                  uint32(unbondingTime),
		CovenantSignatures:             make([]*proto.CovenantSig, 0),
		UnbondingTxBtcConfirmationInfo: nil,
	}

	return unbondingData, nil
}

// --------------------------------------------------------------

// WithdrawableTransactionsFilter sets the filter to only return withdrawable transactions
type WithdrawableTransactionsFilter struct {
	currentBestBlockHeight uint32
}

// StoredTransactionQuery sets the query to get stored transactions
type StoredTransactionQuery struct {
	IndexOffset                    uint64
	NumMaxTransactions             uint64
	Reversed                       bool
	withdrawableTransactionsFilter *WithdrawableTransactionsFilter
}

// StoredTransactionQueryResult is the result of a stored transaction query
type StoredTransactionQueryResult struct {
	Transactions []StoredTransaction
	Total        uint64
}

// WithdrawableTransactionsFilter sets the filter to only return withdrawable transactions.
func (q *StoredTransactionQuery) WithdrawableTransactionsFilter(currentBestBlock uint32) StoredTransactionQuery {
	q.withdrawableTransactionsFilter = &WithdrawableTransactionsFilter{
		currentBestBlockHeight: currentBestBlock,
	}

	return *q
}

// --------------------------------------------------------------

// OutpointUsed returns if an outpoint is used
func (c *TrackedTransactionStore) OutpointUsed(op *wire.OutPoint) (bool, error) {
	used := false

	if err := c.db.View(func(tx kvdb.RTx) error {
		inputsBucket := tx.ReadBucket(inputsDataBucketName)
		if inputsBucket == nil {
			return ErrCorruptedTransactionsDB
		}

		opBytes, err := outpointBytes(op)
		if err != nil {
			return fmt.Errorf("invalid outpoint provided: %w", err)
		}

		res := inputsBucket.Get(opBytes)
		if res != nil {
			used = true
		}
		return nil
	}, func() {}); err != nil {
		return used, fmt.Errorf("failed to get outpoint used: %w", err)
	}

	return used, nil
}

// outpointBytes returns bytes representation of outpoint
func outpointBytes(op *wire.OutPoint) ([]byte, error) {
	var buf bytes.Buffer
	_, err := buf.Write(op.Hash.CloneBytes())
	if err != nil {
		return nil, fmt.Errorf("failed to write hash bytes: %w", err)
	}

	if err := binary.Write(&buf, binary.BigEndian, op.Index); err != nil {
		return nil, fmt.Errorf("failed to write index bytes: %w", err)
	}

	return buf.Bytes(), nil
}

// getInputData returns input data of a transaction
func getInputData(tx *wire.MsgTx) (*inputData, error) {
	var inputs [][]byte

	for _, in := range tx.TxIn {
		opBytes, err := outpointBytes(&in.PreviousOutPoint)
		if err != nil {
			return nil, fmt.Errorf("failed to get input outpoint bytes: %w", err)
		}
		inputs = append(inputs, opBytes)
	}
	txHash := tx.TxHash()

	return &inputData{
		inputs: inputs,
		txHash: txHash.CloneBytes(),
	}, nil
}

// isTimeLockExpired checks if the time lock is expired
func isTimeLockExpired(confirmationBlockHeight uint32, lockTime uint16, currentBestBlockHeight uint32) bool {
	// transaction maybe included/executed only in next possible block
	nexBlockHeight := int64(currentBestBlockHeight) + 1
	pastLock := nexBlockHeight - int64(confirmationBlockHeight) - int64(lockTime)
	return pastLock >= 0
}

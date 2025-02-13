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

type StoredTransactionScanFn func(tx *StoredTransaction) error

type TrackedTransactionStore struct {
	db kvdb.Backend
}

type PubKeySigPair struct {
	Signature *schnorr.Signature
	PubKey    *btcec.PublicKey
}

func NewCovenantMemberSignature(
	sig *schnorr.Signature,
	pubKey *btcec.PublicKey,
) PubKeySigPair {
	return PubKeySigPair{
		sig,
		pubKey,
	}
}

type BtcConfirmationInfo struct {
	Height    uint32
	BlockHash chainhash.Hash
}

type StoredTransaction struct {
	StoredTransactionIdx        uint64
	StakingTx                   *wire.MsgTx
	StakingTxConfirmationInfo   *BtcConfirmationInfo
	UnbondingTxConfirmationInfo *BtcConfirmationInfo
	StakingTime                 uint16
	UnbondingTime               uint16
	StakerAddress               string // Returning address as string, to avoid having to know how to decode address which requires knowing the network we are on
}

// StakingTxConfirmedOnBtc returns true only if staking transaction was sent and confirmed on bitcoin
func (t *StoredTransaction) StakingTxConfirmedOnBtc() bool {
	return t.StakingTxConfirmationInfo != nil
}

// UnbondingTxConfirmedOnBtc returns true only if unbonding transaction was sent and confirmed on bitcoin
func (t *StoredTransaction) UnbondingTxConfirmedOnBtc() bool {
	return t.UnbondingTxConfirmationInfo != nil
}

type WithdrawableTransactionsFilter struct {
	currentBestBlockHeight uint32
}
type StoredTransactionQuery struct {
	IndexOffset                    uint64
	NumMaxTransactions             uint64
	Reversed                       bool
	withdrawableTransactionsFilter *WithdrawableTransactionsFilter
}

func DefaultStoredTransactionQuery() StoredTransactionQuery {
	return StoredTransactionQuery{
		IndexOffset:                    0,
		NumMaxTransactions:             50,
		Reversed:                       false,
		withdrawableTransactionsFilter: nil,
	}
}

func (q *StoredTransactionQuery) WithdrawableTransactionsFilter(currentBestBlock uint32) StoredTransactionQuery {
	q.withdrawableTransactionsFilter = &WithdrawableTransactionsFilter{
		currentBestBlockHeight: currentBestBlock,
	}

	return *q
}

type StoredTransactionQueryResult struct {
	Transactions []StoredTransaction
	Total        uint64
}

// NewTrackedTransactionStore returns a new store backed by db
func NewTrackedTransactionStore(db kvdb.Backend) (*TrackedTransactionStore,
	error) {
	store := &TrackedTransactionStore{db}
	if err := store.initBuckets(); err != nil {
		return nil, err
	}

	return store, nil
}

func (c *TrackedTransactionStore) initBuckets() error {
	return kvdb.Batch(c.db, func(tx kvdb.RwTx) error {
		_, err := tx.CreateTopLevelBucket(transactionBucketName)
		if err != nil {
			return err
		}

		_, err = tx.CreateTopLevelBucket(transactionIndexName)
		if err != nil {
			return err
		}

		_, err = tx.CreateTopLevelBucket(inputsDataBucketName)

		if err != nil {
			return err
		}

		return nil
	})
}

func protoBtcConfirmationInfoToBtcConfirmationInfo(ci *proto.BTCConfirmationInfo) (*BtcConfirmationInfo, error) {
	if ci == nil {
		return nil, nil
	}

	hash, err := chainhash.NewHash(ci.BlockHash)

	if err != nil {
		return nil, err
	}

	return &BtcConfirmationInfo{
		Height:    ci.BlockHeight,
		BlockHash: *hash,
	}, nil
}

func protoTxToStoredTransaction(ttx *proto.TrackedTransaction) (*StoredTransaction, error) {
	var stakingTx wire.MsgTx
	err := stakingTx.Deserialize(bytes.NewReader(ttx.StakingTransaction))

	if err != nil {
		return nil, err
	}

	// var utd *UnbondingStoreData
	uci, err := protoBtcConfirmationInfoToBtcConfirmationInfo(ttx.UnbondingTxBtcConfirmationInfo)
	if err != nil {
		return nil, err
	}
	sci, err := protoBtcConfirmationInfoToBtcConfirmationInfo(ttx.StakingTxBtcConfirmationInfo)
	if err != nil {
		return nil, err
	}

	if ttx.StakingTime > math.MaxUint16 {
		return nil, fmt.Errorf("staking time is too large. Max value is %d", math.MaxUint16)
	}

	return &StoredTransaction{
		StoredTransactionIdx:        ttx.TrackedTransactionIdx,
		StakingTx:                   &stakingTx,
		StakingTxConfirmationInfo:   sci,
		UnbondingTxConfirmationInfo: uci,
		StakingTime:                 uint16(ttx.StakingTime),
		StakerAddress:               ttx.StakerAddress,
	}, nil
}

func uint64KeyToBytes(key uint64) []byte {
	var keyBytes = make([]byte, 8)
	binary.BigEndian.PutUint64(keyBytes, key)
	return keyBytes
}

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

func getNumTx(txIdxBucket walletdb.ReadBucket) uint64 {
	// we are starting indexing transactions from 1, and nextTxKey always return next key
	// which should be used when indexing transaction, so to get number of transactions
	// we need to subtract 1
	return nextTxKey(txIdxBucket) - 1
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
		return err
	}

	nextTxKeyBytes := uint64KeyToBytes(nextTxKey)

	err = txBucket.Put(nextTxKeyBytes, marshalled)

	if err != nil {
		return err
	}

	err = txIdxBucket.Put(txHashBytes, nextTxKeyBytes)

	if err != nil {
		return err
	}

	if id != nil {
		inputDataBucket := rwTx.ReadWriteBucket(inputsDataBucketName)
		if inputDataBucket == nil {
			return ErrCorruptedTransactionsDB
		}

		for _, input := range id.inputs {
			// save all the inputs to the transaction
			err = inputDataBucket.Put(input, txHashBytes)

			if err != nil {
				return err
			}
		}
	}

	// increment counter for the next transaction
	return txIdxBucket.Put(numTxKey, uint64KeyToBytes(nextTxKey+1))
}

func (c *TrackedTransactionStore) addTransactionInternal(
	txHashBytes []byte,
	tt *proto.TrackedTransaction,
	id *inputData,
) error {
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

func deleteTrackedTransaction(
	rwTx kvdb.RwTx,
	txIdxBucket walletdb.ReadWriteBucket,
	txBucket walletdb.ReadWriteBucket,
	txHashBytes []byte,
) error {
	// 1. Get current number of transactions
	numTxBytes := txIdxBucket.Get(numTxKey)
	if numTxBytes == nil {
		return ErrCorruptedTransactionsDB
	}
	currentNumTx := binary.BigEndian.Uint64(numTxBytes)

	// 2. Delete transaction data
	indexBytes := txIdxBucket.Get(txHashBytes)
	if indexBytes == nil {
		return fmt.Errorf("transaction not found for hash")
	}

	if err := txBucket.Delete(indexBytes); err != nil {
		return fmt.Errorf("failed to delete transaction data: %w", err)
	}

	if err := txIdxBucket.Delete(txHashBytes); err != nil {
		return fmt.Errorf("failed to delete transaction index: %w", err)
	}

	// 3. Delete input data
	inputDataBucket := rwTx.ReadWriteBucket(inputsDataBucketName)
	if inputDataBucket == nil {
		return ErrCorruptedTransactionsDB
	}

	cursor := inputDataBucket.ReadCursor()
	for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
		if bytes.Equal(v, txHashBytes) {
			if err := inputDataBucket.Delete(k); err != nil {
				return fmt.Errorf("failed to delete input data: %w", err)
			}
		}
	}

	// 4. Update number of transactions
	if currentNumTx > 0 {
		if err := txIdxBucket.Put(numTxKey, uint64KeyToBytes(currentNumTx-1)); err != nil {
			return fmt.Errorf("failed to update transaction count: %w", err)
		}
	}

	return nil
}

func (c *TrackedTransactionStore) deleteTransasctionInternal(txHash []byte) error {
	return kvdb.Batch(c.db, func(tx kvdb.RwTx) error {
		transactionsBucketIdxBucket := tx.ReadWriteBucket(transactionIndexName)
		if transactionsBucketIdxBucket == nil {
			return ErrCorruptedTransactionsDB
		}

		// check if transaction exists
		if transactionsBucketIdxBucket.Get(txHash) == nil {
			return fmt.Errorf("transaction not found")
		}

		transactionsBucket := tx.ReadWriteBucket(transactionBucketName)
		if transactionsBucket == nil {
			return ErrCorruptedTransactionsDB
		}

		return deleteTrackedTransaction(tx, transactionsBucketIdxBucket, transactionsBucket, txHash)
	})
}

func CreateTrackedTransaction(
	btcTx *wire.MsgTx,
	stakingTime uint16,
	stakerAddress btcutil.Address,
) (*StoredTransaction, error) {
	serializedTx, err := utils.SerializeBtcTransaction(btcTx)
	if err != nil {
		return nil, err
	}

	msg := proto.TrackedTransaction{
		// Setting it to 0, proper number will be filled by `addTransactionInternal`
		TrackedTransactionIdx: 0,
		StakingTransaction:    serializedTx,
		StakerAddress:         stakerAddress.EncodeAddress(),
		StakingTime:           uint32(stakingTime),
	}

	return protoTxToStoredTransaction(&msg)
}

type inputData struct {
	inputs [][]byte
	txHash []byte
}

func outpointBytes(op *wire.OutPoint) ([]byte, error) {
	var buf bytes.Buffer
	_, err := buf.Write(op.Hash.CloneBytes())
	if err != nil {
		return nil, err
	}

	err = binary.Write(&buf, binary.BigEndian, op.Index)

	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func getInputData(tx *wire.MsgTx) (*inputData, error) {
	var inputs [][]byte

	for _, in := range tx.TxIn {
		opBytes, err := outpointBytes(&in.PreviousOutPoint)
		if err != nil {
			return nil, err
		}
		inputs = append(inputs, opBytes)
	}
	txHash := tx.TxHash()

	return &inputData{
		inputs: inputs,
		txHash: txHash.CloneBytes(),
	}, nil
}

// AddTransactionSentToBabylon adds a transaction sent to Babylon
func (c *TrackedTransactionStore) AddTransactionSentToBabylon(
	btcTx *wire.MsgTx,
	stakingTime uint16,
	stakerAddress btcutil.Address,
	unbondingTime uint16,
) error {
	txHash := btcTx.TxHash()
	txHashBytes := txHash[:]
	serializedTx, err := utils.SerializeBtcTransaction(btcTx)
	if err != nil {
		return fmt.Errorf("failed to serialize Bitcoin transaction: %w", err)
	}

	msg := proto.TrackedTransaction{
		// Setting it to 0, proper number will be filled by `addTransactionInternal`
		TrackedTransactionIdx: 0,
		StakingTransaction:    serializedTx,
		StakerAddress:         stakerAddress.EncodeAddress(),
		StakingTime:           uint32(stakingTime),
		UnbondingTime:         uint32(unbondingTime),
	}

	inputData, err := getInputData(btcTx)

	if err != nil {
		return fmt.Errorf("failed to get input data: %w", err)
	}

	return c.addTransactionInternal(
		txHashBytes, &msg, inputData,
	)
}

// DeleteTransactionSentToBabylon deletes a tracked transaction by its hash
func (c *TrackedTransactionStore) DeleteTransactionSentToBabylon(txHash *chainhash.Hash) error {
	if txHash == nil {
		return fmt.Errorf("transaction hash cannot be nil")
	}

	txHashBytes := txHash[:]
	return c.deleteTransasctionInternal(txHashBytes)
}

// setTxState sets the state of a transaction
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
			return err
		}

		var storedTx proto.TrackedTransaction
		err = pm.Unmarshal(maybeTx, &storedTx)
		if err != nil {
			return ErrCorruptedTransactionsDB
		}

		if err := stateTransitionFn(&storedTx); err != nil {
			return err
		}

		marshalled, err := pm.Marshal(&storedTx)

		if err != nil {
			return err
		}

		err = transactionsBucket.Put(txKey, marshalled)

		if err != nil {
			return err
		}

		return nil
	})
}

// SetTxConfirmed sets the state of a transaction
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

func (c *TrackedTransactionStore) SetDelegationActiveOnBabylonAndConfirmedOnBtc(
	txHash *chainhash.Hash,
	blockHash *chainhash.Hash,
	blockHeight uint32,
) error {
	setDelegationActiveOnBabylon := func(tx *proto.TrackedTransaction) error {
		tx.StakingTxBtcConfirmationInfo = &proto.BTCConfirmationInfo{
			BlockHash:   blockHash.CloneBytes(),
			BlockHeight: blockHeight,
		}
		return nil
	}

	return c.setTxState(txHash, setDelegationActiveOnBabylon)
}

func (c *TrackedTransactionStore) SetTxUnbondingConfirmedOnBtc(
	txHash *chainhash.Hash,
	blockHash *chainhash.Hash,
	blockHeight uint32,
) error {
	setUnbondingConfirmedOnBtc := func(tx *proto.TrackedTransaction) error {
		tx.UnbondingTxBtcConfirmationInfo = &proto.BTCConfirmationInfo{
			BlockHash:   blockHash.CloneBytes(),
			BlockHeight: blockHeight,
		}
		return nil
	}

	return c.setTxState(txHash, setUnbondingConfirmedOnBtc)
}

func (c *TrackedTransactionStore) GetTransaction(txHash *chainhash.Hash) (*StoredTransaction, error) {
	var storedTx *StoredTransaction
	txHashBytes := txHash.CloneBytes()

	err := c.db.View(func(tx kvdb.RTx) error {
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
			return err
		}

		var storedTxProto proto.TrackedTransaction
		err = pm.Unmarshal(maybeTx, &storedTxProto)
		if err != nil {
			return ErrCorruptedTransactionsDB
		}

		txFromDB, err := protoTxToStoredTransaction(&storedTxProto)
		if err != nil {
			return err
		}

		storedTx = txFromDB
		return nil
	}, func() {})

	if err != nil {
		return nil, err
	}

	return storedTx, nil
}

func (c *TrackedTransactionStore) GetAllStoredTransactions() ([]StoredTransaction, error) {
	q := DefaultStoredTransactionQuery()
	// MaxUint64 indicates we will scan over all transactions
	q.NumMaxTransactions = math.MaxUint64

	resp, err := c.QueryStoredTransactions(q)
	if err != nil {
		return nil, err
	}

	return resp.Transactions, nil
}

func isTimeLockExpired(confirmationBlockHeight uint32, lockTime uint16, currentBestBlockHeight uint32) bool {
	// transaction maybe included/executed only in next possible block
	nexBlockHeight := int64(currentBestBlockHeight) + 1
	pastLock := nexBlockHeight - int64(confirmationBlockHeight) - int64(lockTime)
	return pastLock >= 0
}

func (c *TrackedTransactionStore) QueryStoredTransactions(q StoredTransactionQuery) (StoredTransactionQueryResult, error) {
	var resp StoredTransactionQueryResult

	err := c.db.View(func(tx kvdb.RTx) error {
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

			err := pm.Unmarshal(transaction, &protoTx)
			if err != nil {
				return false, err
			}

			txFromDB, err := protoTxToStoredTransaction(&protoTx)

			if err != nil {
				return false, err
			}

			// we have query only for withdrawable transaction i.e transactions which
			// either in states and which timelock has expired
			if q.withdrawableTransactionsFilter != nil {
				var confirmationHeight uint32
				var scriptTimeLock uint16

				switch {
				case txFromDB.StakingTxConfirmedOnBtc() && !txFromDB.UnbondingTxConfirmedOnBtc():
					scriptTimeLock = txFromDB.StakingTime
					confirmationHeight = txFromDB.StakingTxConfirmationInfo.Height
				case txFromDB.StakingTxConfirmedOnBtc() && txFromDB.UnbondingTxConfirmedOnBtc():
					scriptTimeLock = txFromDB.UnbondingTime
					confirmationHeight = txFromDB.UnbondingTxConfirmationInfo.Height
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
			return err
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
	})

	if err != nil {
		return resp, err
	}

	return resp, nil
}

func (c *TrackedTransactionStore) ScanTrackedTransactions(scanFunc StoredTransactionScanFn, reset func()) error {
	return kvdb.View(c.db, func(tx kvdb.RTx) error {
		transactionsBucket := tx.ReadBucket(transactionBucketName)

		if transactionsBucket == nil {
			return ErrCorruptedTransactionsDB
		}

		return transactionsBucket.ForEach(func(_, v []byte) error {
			var storedTxProto proto.TrackedTransaction
			err := pm.Unmarshal(v, &storedTxProto)

			if err != nil {
				return ErrCorruptedTransactionsDB
			}

			txFromDB, err := protoTxToStoredTransaction(&storedTxProto)

			if err != nil {
				return err
			}

			return scanFunc(txFromDB)
		})
	}, reset)
}

func (c *TrackedTransactionStore) OutpointUsed(op *wire.OutPoint) (bool, error) {
	used := false

	err := c.db.View(func(tx kvdb.RTx) error {
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
	}, func() {})

	return used, err
}

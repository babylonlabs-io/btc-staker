package stakerdb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"

	"github.com/babylonlabs-io/btc-staker/proto"
	"github.com/babylonlabs-io/btc-staker/utils"
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

// StoredTransactionScanFn is a function which is called for each transaction which is being tracked
type StoredTransactionScanFn func(tx *StoredTransaction) error

// TrackedTransactionStore is a store which stores transactions which are being tracked
type TrackedTransactionStore struct {
	db kvdb.Backend
}

// StoredTransaction is a struct which contains the information about a
type StoredTransaction struct {
	StoredTransactionIdx uint64
	StakingTx            *wire.MsgTx
	StakerAddress        string // Returning address as string, to avoid having to know how to decode address which requires knowing the network we are on
}

// StoredTransactionQuery is a struct which contains the parameters for a query
type StoredTransactionQuery struct {
	IndexOffset        uint64
	NumMaxTransactions uint64
	Reversed           bool
}

// StoredTransactionQueryResult is a struct which contains a slice of
// StoredTransaction and total number of transactions
type StoredTransactionQueryResult struct {
	Transactions []StoredTransaction
	Total        uint64
}

// DefaultStoredTransactionQuery returns a default query which returns 50 transactions
func DefaultStoredTransactionQuery() StoredTransactionQuery {
	return StoredTransactionQuery{
		IndexOffset:        0,
		NumMaxTransactions: 50,
		Reversed:           false,
	}
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

// initBuckets creates the buckets needed by the store
func (c *TrackedTransactionStore) initBuckets() error {
	return kvdb.Batch(c.db, func(tx kvdb.RwTx) error {
		_, err := tx.CreateTopLevelBucket(transactionBucketName)
		if err != nil {
			return fmt.Errorf("failed to create transactions bucket: %w", err)
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

// protoTxToStoredTransaction converts a TrackedTransaction to a StoredTransaction
func protoTxToStoredTransaction(ttx *proto.TrackedTransaction) (*StoredTransaction, error) {
	var stakingTx wire.MsgTx
	if err := stakingTx.Deserialize(bytes.NewReader(ttx.StakingTransaction)); err != nil {
		return nil, fmt.Errorf("failed to deserialize staking transaction: %w", err)
	}

	return &StoredTransaction{
		StoredTransactionIdx: ttx.TrackedTransactionIdx,
		StakingTx:            &stakingTx,
		StakerAddress:        ttx.StakerAddress,
	}, nil
}

// uint64KeyToBytes converts a uint64 to a byte slice
func uint64KeyToBytes(key uint64) []byte {
	var keyBytes = make([]byte, 8)
	binary.BigEndian.PutUint64(keyBytes, key)
	return keyBytes
}

// nextTxKey returns the next key to use for a transaction
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

// getNumTx returns number of transactions stored in the database
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

// saveTrackedTransaction saves a tracked transaction to the database
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
		return fmt.Errorf("failed to save transaction: %w", err)
	}

	if err := txIdxBucket.Put(txHashBytes, nextTxKeyBytes); err != nil {
		return fmt.Errorf("failed to save transaction index: %w", err)
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

// addTransactionInternal adds a transaction to the database
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

// deleteTrackedTransaction deletes a transaction from the database
func deleteTrackedTransaction(
	rwTx kvdb.RwTx,
	txIdxBucket walletdb.ReadWriteBucket,
	txBucket walletdb.ReadWriteBucket,
	txHashBytes []byte,
) error {
	// Get current number of transactions
	numTxBytes := txIdxBucket.Get(numTxKey)
	if numTxBytes == nil {
		return ErrCorruptedTransactionsDB
	}
	currentNumTx := binary.BigEndian.Uint64(numTxBytes)

	// Delete transaction data
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

	// Delete input data
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

	// Update number of transactions
	if currentNumTx > 0 {
		if err := txIdxBucket.Put(numTxKey, uint64KeyToBytes(currentNumTx-1)); err != nil {
			return fmt.Errorf("failed to update transaction count: %w", err)
		}
	}

	return nil
}

// deleteTransasctionInternal deletes a transaction from the database
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

// CreateTrackedTransaction creates a new tracked transaction
func CreateTrackedTransaction(
	btcTx *wire.MsgTx,
	stakerAddress btcutil.Address,
) (*StoredTransaction, error) {
	serializedTx, err := utils.SerializeBtcTransaction(btcTx)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Bitcoin transaction: %w", err)
	}

	msg := proto.TrackedTransaction{
		// Setting it to 0, proper number will be filled by `addTransactionInternal`
		TrackedTransactionIdx: 0,
		StakingTransaction:    serializedTx,
		StakerAddress:         stakerAddress.EncodeAddress(),
	}

	return protoTxToStoredTransaction(&msg)
}

// inputData is the input data of a transaction
type inputData struct {
	inputs [][]byte
	txHash []byte
}

// outpointBytes converts an outpoint to a byte slice
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

// getInputData returns the input data of a transaction
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
	stakerAddress btcutil.Address,
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

// GetTransaction retrieves a transaction by its hash
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
		err = pm.Unmarshal(maybeTx, &storedTxProto)
		if err != nil {
			return fmt.Errorf("failed to unmarshal transaction: %w", err)
		}

		txFromDB, err := protoTxToStoredTransaction(&storedTxProto)
		if err != nil {
			return fmt.Errorf("failed to convert transaction to stored transaction: %w", err)
		}

		storedTx = txFromDB
		return nil
	}, func() {}); err != nil {
		return nil, fmt.Errorf("failed to get transaction: %w", err)
	}

	return storedTx, nil
}

// GetAllStoredTransactions returns all stored transactions
func (c *TrackedTransactionStore) GetAllStoredTransactions() ([]StoredTransaction, error) {
	q := DefaultStoredTransactionQuery()
	// MaxUint64 indicates we will scan over all transactions
	q.NumMaxTransactions = math.MaxUint64

	resp, err := c.QueryStoredTransactions(q)
	if err != nil {
		return nil, fmt.Errorf("failed to query stored transactions: %w", err)
	}

	return resp.Transactions, nil
}

// QueryStoredTransactions queries stored transactions
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
				return false, fmt.Errorf("failed to convert transaction to stored transaction: %w", err)
			}

			resp.Transactions = append(resp.Transactions, *txFromDB)
			return true, nil
		}

		if err := paginator.query(accumulateTransactions); err != nil {
			return fmt.Errorf("failed to query stored transactions: %w", err)
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

// ScanTrackedTransactions iterates over all stored transactions
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

// OutpointUsed checks if an outpoint is used by a tracked transaction
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

		if inputsBucket.Get(opBytes) != nil {
			used = true
		}

		return nil
	}, func() {})

	return used, err
}

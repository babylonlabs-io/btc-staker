package stakerdb_test

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/babylonlabs-io/babylon/v4/testutil/datagen"
	protobufs "github.com/babylonlabs-io/btc-staker/proto"
	"github.com/babylonlabs-io/btc-staker/stakerdb"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/kvdb"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// TestMigrateTrackedTransactions_EmptyDatabase tests migration on an empty database
func TestMigrateTrackedTransactions_EmptyDatabase(t *testing.T) {
	t.Parallel()
	store := MakeTestStore(t)

	// Run migration on empty database
	result, err := store.MigrateTrackedTransactions()
	require.NoError(t, err)
	require.NotNil(t, result)

	// Should have no transactions to process
	require.Equal(t, 0, result.ProcessedCount)
	require.Equal(t, 0, result.MigratedCount)
	require.Equal(t, 0, result.SkippedCount)
	require.Equal(t, 0, result.ErrorCount)
}

// TestMigrateTrackedTransactions_WithOldFormatData tests migration with old format transactions
func TestMigrateTrackedTransactions_WithOldFormatData(t *testing.T) {
	t.Parallel()
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	store := MakeTestStore(t)

	// Generate realistic old format transactions using datagen
	oldTransactions := genOldFormatTransactions(t, r, 2)

	// Manually insert old format data into the database
	err := seedDatabaseWithOldFormat(store, oldTransactions)
	require.NoError(t, err)

	// Run migration
	result, err := store.MigrateTrackedTransactions()
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify migration results
	require.Equal(t, 2, result.ProcessedCount)
	require.Equal(t, 2, result.MigratedCount)
	require.Equal(t, 0, result.SkippedCount)
	require.Equal(t, 0, result.ErrorCount)

	// Verify the migrated data
	verifyMigratedTransactions(t, store, oldTransactions)
}

// TestMigrateTrackedTransactions_WithNewFormatData tests migration when data is already in new format
func TestMigrateTrackedTransactions_WithNewFormatData(t *testing.T) {
	t.Parallel()
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	store := MakeTestStore(t)

	// Generate realistic new format transactions using datagen
	newTransactions := genNewFormatTransactions(t, r, 2)

	// Manually insert new format data into the database
	err := seedDatabaseWithNewFormat(store, newTransactions)
	require.NoError(t, err)

	// Run migration
	result, err := store.MigrateTrackedTransactions()
	require.NoError(t, err)
	require.NotNil(t, result)

	// Should skip already migrated transactions
	require.Equal(t, 2, result.ProcessedCount)
	require.Equal(t, 0, result.MigratedCount)
	require.Equal(t, 2, result.SkippedCount)
	require.Equal(t, 0, result.ErrorCount)
}

// TestMigrateTrackedTransactions_MixedFormatData tests migration with both old and new format data
func TestMigrateTrackedTransactions_MixedFormatData(t *testing.T) {
	t.Parallel()
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	store := MakeTestStore(t)

	// Generate old and new format transactions with different indices
	oldTxs := genOldFormatTransactions(t, r, 1)
	newTxs := genNewFormatTransactions(t, r, 1)
	// Adjust new transaction index to avoid conflict
	newTxs[0].TrackedTransactionIdx = 2

	// Insert both formats
	err := seedDatabaseWithOldFormat(store, oldTxs)
	require.NoError(t, err)
	err = seedDatabaseWithNewFormat(store, newTxs)
	require.NoError(t, err)

	// Run migration
	result, err := store.MigrateTrackedTransactions()
	require.NoError(t, err)
	require.NotNil(t, result)

	// Should migrate old and skip new
	require.Equal(t, 2, result.ProcessedCount)
	require.Equal(t, 1, result.MigratedCount)
	require.Equal(t, 1, result.SkippedCount)
	require.Equal(t, 0, result.ErrorCount)
}

// TestMigrateTrackedTransactions_InvalidData tests migration with invalid/corrupted data
func TestMigrateTrackedTransactions_InvalidData(t *testing.T) {
	t.Parallel()
	store := MakeTestStore(t)

	// Insert invalid protobuf data
	err := seedDatabaseWithInvalidData(store)
	require.NoError(t, err)

	// Run migration
	result, err := store.MigrateTrackedTransactions()
	require.NoError(t, err)
	require.NotNil(t, result)

	// Should have error processing invalid data
	require.Equal(t, 1, result.ProcessedCount)
	require.Equal(t, 0, result.MigratedCount)
	require.Equal(t, 0, result.SkippedCount)
	require.Equal(t, 1, result.ErrorCount)
}

// TestMigrateTrackedTransactions_MissingFields tests migration with missing required fields
func TestMigrateTrackedTransactions_MissingFields(t *testing.T) {
	t.Parallel()
	store := MakeTestStore(t)

	// Create old format transactions with missing required fields
	oldTransactions := []*protobufs.OldTrackedTransaction{
		{
			// Missing TrackedTransactionIdx
			StakingTransaction: []byte("old_staking_tx_1"),
			StakerAddress:      "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
		},
		{
			TrackedTransactionIdx: 2,
			// Missing StakingTransaction
			StakerAddress: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
		},
		{
			TrackedTransactionIdx: 3,
			StakingTransaction:    []byte("old_staking_tx_3"),
			// Missing StakerAddress
		},
	}

	// Insert transactions with missing fields
	err := seedDatabaseWithOldFormat(store, oldTransactions)
	require.NoError(t, err)

	// Run migration
	result, err := store.MigrateTrackedTransactions()
	require.NoError(t, err)
	require.NotNil(t, result)

	// Should have errors for all transactions due to missing required fields
	require.Equal(t, 3, result.ProcessedCount)
	require.Equal(t, 0, result.MigratedCount)
	require.Equal(t, 0, result.SkippedCount)
	require.Equal(t, 3, result.ErrorCount)
}

// createMockBitcoinTx creates a mock Bitcoin transaction for testing
func createMockBitcoinTx() *wire.MsgTx {
	return &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  [32]byte{},
					Index: 0,
				},
				SignatureScript: []byte{},
				Sequence:        wire.MaxTxInSequenceNum,
			},
		},
		TxOut: []*wire.TxOut{
			{
				Value:    100000000,
				PkScript: make([]byte, 25),
			},
		},
		LockTime: 0,
	}
}

// TestMigrateTrackedTransactions_RealData tests migration with data added through public API
func TestMigrateTrackedTransactions_RealData(t *testing.T) {
	t.Parallel()
	store := MakeTestStore(t)

	// Use the public API to add transactions (this will use current format)
	mockTx := createMockBitcoinTx()

	// Create proper staker address
	stakerAddr := "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
	addr, err := btcutil.DecodeAddress(stakerAddr, nil)
	require.NoError(t, err)

	// Add transaction using public API
	err = store.AddTransactionSentToBabylon(mockTx, addr)
	require.NoError(t, err)

	// Add another transaction
	mockTx2 := createMockBitcoinTx()
	// Modify the transaction to make it unique
	mockTx2.TxIn[0].PreviousOutPoint.Index = 1

	stakerAddr2 := "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
	addr2, err := btcutil.DecodeAddress(stakerAddr2, nil)
	require.NoError(t, err)

	err = store.AddTransactionSentToBabylon(mockTx2, addr2)
	require.NoError(t, err)

	// Run migration - should detect that transactions are already in correct format
	result, err := store.MigrateTrackedTransactions()
	require.NoError(t, err)
	require.NotNil(t, result)

	// Should skip transactions that are already in new format
	require.Equal(t, 2, result.ProcessedCount)
	require.Equal(t, 0, result.MigratedCount) // Should be 0 since they're already new format
	require.Equal(t, 2, result.SkippedCount)
	require.Equal(t, 0, result.ErrorCount)
}

// genOldFormatTransactions generates old format transactions for testing
func genOldFormatTransactions(t *testing.T, r *rand.Rand, n int) []*protobufs.OldTrackedTransaction {
	oldTxs := make([]*protobufs.OldTrackedTransaction, n)
	for i := 0; i < n; i++ {
		btcTx := datagen.GenRandomTx(r)
		stakerAddr, err := datagen.GenRandomBTCAddress(r, &chaincfg.MainNetParams)
		require.NoError(t, err)

		// Serialize the Bitcoin transaction
		var buf bytes.Buffer
		err = btcTx.Serialize(&buf)
		require.NoError(t, err)

		oldTxs[i] = &protobufs.OldTrackedTransaction{
			TrackedTransactionIdx:      uint64(i + 1),
			StakingTransaction:         buf.Bytes(),
			StakerAddress:              stakerAddr.String(),
			StakingOutputIdx:           uint32(r.Intn(3)),
			StakingTime:                uint32(time.Now().Unix()),
			FinalityProvidersBtcPks:    [][]byte{datagen.GenRandomByteArray(r, 33)},
			BtcSigType:                 1,
			BtcSigOverBbnStakerAddr:    datagen.GenRandomByteArray(r, 64),
			State:                      protobufs.TransactionState_CONFIRMED_ON_BTC,
			Watched:                    r.Intn(2) == 1,
			BabylonBTCDelegationTxHash: datagen.GenRandomHexStr(r, 32),
		}
	}
	return oldTxs
}

// genNewFormatTransactions generates new format transactions for testing
func genNewFormatTransactions(t *testing.T, r *rand.Rand, n int) []*protobufs.TrackedTransaction {
	newTxs := make([]*protobufs.TrackedTransaction, n)
	for i := 0; i < n; i++ {
		btcTx := datagen.GenRandomTx(r)
		stakerAddr, err := datagen.GenRandomBTCAddress(r, &chaincfg.MainNetParams)
		require.NoError(t, err)

		// Serialize the Bitcoin transaction
		var buf bytes.Buffer
		err = btcTx.Serialize(&buf)
		require.NoError(t, err)

		newTxs[i] = &protobufs.TrackedTransaction{
			TrackedTransactionIdx: uint64(i + 1),
			StakingTransaction:    buf.Bytes(),
			StakerAddress:         stakerAddr.String(),
		}
	}
	return newTxs
}

// uint64KeyToBytes converts a uint64 to a byte slice (copied from store implementation)
func uint64KeyToBytes(key uint64) []byte {
	var keyBytes = make([]byte, 8)
	binary.BigEndian.PutUint64(keyBytes, key)
	return keyBytes
}

// getDBFromStore extracts the database backend from the store using reflection
func getDBFromStore(store *stakerdb.TrackedTransactionStore) kvdb.Backend {
	v := reflect.ValueOf(store).Elem()
	dbField := v.FieldByName("db")
	if !dbField.IsValid() {
		panic("db field not found in TrackedTransactionStore")
	}

	// Use unsafe to access private field
	dbPtr := unsafe.Pointer(dbField.UnsafeAddr())
	db := *(*kvdb.Backend)(dbPtr)
	return db
}

// seedDatabaseWithOldFormat manually inserts old format transactions into the database
func seedDatabaseWithOldFormat(store *stakerdb.TrackedTransactionStore, transactions []*protobufs.OldTrackedTransaction) error {
	db := getDBFromStore(store)

	return kvdb.Batch(db, func(tx kvdb.RwTx) error {
		// Get or create the transactions bucket
		transactionBucket, err := tx.CreateTopLevelBucket([]byte("transactions"))
		if err != nil {
			// Bucket might already exist, try to get it
			transactionBucket = tx.ReadWriteBucket([]byte("transactions"))
			if transactionBucket == nil {
				return err
			}
		}

		// Get or create the transaction index bucket
		transactionIndexBucket, err := tx.CreateTopLevelBucket([]byte("transactionIdx"))
		if err != nil {
			// Bucket might already exist, try to get it
			transactionIndexBucket = tx.ReadWriteBucket([]byte("transactionIdx"))
			if transactionIndexBucket == nil {
				return err
			}
		}

		for _, oldTx := range transactions {
			// Marshal old format transaction
			data, err := proto.Marshal(oldTx)
			if err != nil {
				return err
			}

			// Store with the transaction index as key
			key := uint64KeyToBytes(oldTx.TrackedTransactionIdx)
			if err := transactionBucket.Put(key, data); err != nil {
				return err
			}

			// Create a dummy hash for indexing (since we don't have the real Bitcoin transaction hash)
			dummyHash := make([]byte, 32)
			binary.BigEndian.PutUint64(dummyHash[24:], oldTx.TrackedTransactionIdx) // Put index in last 8 bytes

			// Store the index mapping
			if err := transactionIndexBucket.Put(dummyHash, key); err != nil {
				return err
			}
		}

		// Update the transaction counter to reflect the highest transaction index
		if len(transactions) > 0 {
			maxIdx := uint64(0)
			for _, tx := range transactions {
				if tx.TrackedTransactionIdx > maxIdx {
					maxIdx = tx.TrackedTransactionIdx
				}
			}
			// Set the counter to be ready for the next transaction
			counterKey := []byte("ntk")
			if err := transactionIndexBucket.Put(counterKey, uint64KeyToBytes(maxIdx+1)); err != nil {
				return err
			}
		}

		return nil
	})
}

// seedDatabaseWithNewFormat manually inserts new format transactions into the database
func seedDatabaseWithNewFormat(store *stakerdb.TrackedTransactionStore, transactions []*protobufs.TrackedTransaction) error {
	db := getDBFromStore(store)

	return kvdb.Batch(db, func(tx kvdb.RwTx) error {
		// Get or create the transactions bucket
		transactionBucket, err := tx.CreateTopLevelBucket([]byte("transactions"))
		if err != nil {
			// Bucket might already exist, try to get it
			transactionBucket = tx.ReadWriteBucket([]byte("transactions"))
			if transactionBucket == nil {
				return err
			}
		}

		// Get or create the transaction index bucket
		transactionIndexBucket, err := tx.CreateTopLevelBucket([]byte("transactionIdx"))
		if err != nil {
			// Bucket might already exist, try to get it
			transactionIndexBucket = tx.ReadWriteBucket([]byte("transactionIdx"))
			if transactionIndexBucket == nil {
				return err
			}
		}

		for _, newTx := range transactions {
			// Marshal new format transaction
			data, err := proto.Marshal(newTx)
			if err != nil {
				return err
			}

			// Store with the transaction index as key
			key := uint64KeyToBytes(newTx.TrackedTransactionIdx)
			if err := transactionBucket.Put(key, data); err != nil {
				return err
			}

			// Create a dummy hash for indexing (since we don't have the real Bitcoin transaction hash)
			dummyHash := make([]byte, 32)
			binary.BigEndian.PutUint64(dummyHash[24:], newTx.TrackedTransactionIdx) // Put index in last 8 bytes

			// Store the index mapping
			if err := transactionIndexBucket.Put(dummyHash, key); err != nil {
				return err
			}
		}

		// Update the transaction counter to reflect the highest transaction index
		if len(transactions) > 0 {
			maxIdx := uint64(0)
			for _, tx := range transactions {
				if tx.TrackedTransactionIdx > maxIdx {
					maxIdx = tx.TrackedTransactionIdx
				}
			}
			// Set the counter to be ready for the next transaction
			counterKey := []byte("ntk")
			if err := transactionIndexBucket.Put(counterKey, uint64KeyToBytes(maxIdx+1)); err != nil {
				return err
			}
		}

		return nil
	})
}

// seedDatabaseWithInvalidData inserts invalid protobuf data
func seedDatabaseWithInvalidData(store *stakerdb.TrackedTransactionStore) error {
	db := getDBFromStore(store)

	return kvdb.Batch(db, func(tx kvdb.RwTx) error {
		// Get or create the transactions bucket
		transactionBucket, err := tx.CreateTopLevelBucket([]byte("transactions"))
		if err != nil {
			// Bucket might already exist, try to get it
			transactionBucket = tx.ReadWriteBucket([]byte("transactions"))
			if transactionBucket == nil {
				return err
			}
		}

		// Insert corrupted protobuf data
		corruptedData := []byte{0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8}
		key := uint64KeyToBytes(1)
		return transactionBucket.Put(key, corruptedData)
	})
}

// verifyMigratedTransactions verifies that the migration preserved essential data
func verifyMigratedTransactions(t *testing.T, store *stakerdb.TrackedTransactionStore, originalTransactions []*protobufs.OldTrackedTransaction) {
	// Get all transactions from the store using the proper API
	result, err := store.QueryStoredTransactions(stakerdb.DefaultStoredTransactionQuery())
	require.NoError(t, err)
	require.Len(t, result.Transactions, len(originalTransactions))

	for i, tx := range result.Transactions {
		original := originalTransactions[i]

		// Verify essential fields were preserved
		require.Equal(t, original.TrackedTransactionIdx, tx.StoredTransactionIdx)
		require.Equal(t, original.StakerAddress, tx.StakerAddress)

		// Verify staking transaction was preserved by serializing and comparing
		var buf bytes.Buffer
		err := tx.StakingTx.Serialize(&buf)
		require.NoError(t, err)
		require.Equal(t, original.StakingTransaction, buf.Bytes())
	}
}

package stakerdb_test

import (
	"errors"
	"math/rand"
	"testing"
	"time"

	"github.com/babylonlabs-io/babylon/v3/testutil/datagen"
	"github.com/babylonlabs-io/btc-staker/stakercfg"
	"github.com/babylonlabs-io/btc-staker/stakerdb"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/stretchr/testify/require"
)

func MakeTestStore(t *testing.T) *stakerdb.TrackedTransactionStore {
	// First, create a temporary directory to be used for the duration of
	// this test.
	tempDirName := t.TempDir()

	cfg := stakercfg.DefaultDBConfig()

	cfg.DBPath = tempDirName

	backend, err := stakercfg.GetDBBackend(&cfg)
	require.NoError(t, err)

	t.Cleanup(func() {
		backend.Close()
	})

	store, err := stakerdb.NewTrackedTransactionStore(backend)
	require.NoError(t, err)

	return store
}

func genStoredTransaction(t *testing.T, r *rand.Rand) *stakerdb.StoredTransaction {
	btcTx := datagen.GenRandomTx(r)
	stakerAddr, err := datagen.GenRandomBTCAddress(r, &chaincfg.MainNetParams)
	require.NoError(t, err)

	return &stakerdb.StoredTransaction{
		StakingTx:     btcTx,
		StakerAddress: stakerAddr.String(),
	}
}

func genNStoredTransactions(t *testing.T, r *rand.Rand, n int) []*stakerdb.StoredTransaction {
	storedTxs := make([]*stakerdb.StoredTransaction, n)

	for i := 0; i < n; i++ {
		storedTxs[i] = genStoredTransaction(t, r)
	}

	return storedTxs
}

func TestEmptyStore(t *testing.T) {
	t.Parallel()
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	s := MakeTestStore(t)
	hash := datagen.GenRandomBtcdHash(r)
	tx, err := s.GetTransaction(&hash)
	require.Nil(t, tx)
	require.Error(t, err)
	require.True(t, errors.Is(err, stakerdb.ErrTransactionNotFound))
}

func FuzzStoringTxs(f *testing.F) {
	// only 3 seeds as this is pretty slow test opening/closing db
	datagen.AddRandomSeedsToFuzzer(f, 3)

	f.Fuzz(func(t *testing.T, seed int64) {
		r := rand.New(rand.NewSource(seed))
		s := MakeTestStore(t)
		maxCreatedTx := 30
		numTx := r.Intn(maxCreatedTx) + 1
		generatedStoredTxs := genNStoredTransactions(t, r, numTx)

		for _, storedTx := range generatedStoredTxs {
			stakerAddr, err := btcutil.DecodeAddress(storedTx.StakerAddress, &chaincfg.MainNetParams)
			require.NoError(t, err)
			err = s.AddTransactionSentToBabylon(
				storedTx.StakingTx,
				stakerAddr,
			)
			require.NoError(t, err)
		}
		var expectedIdx uint64 = 1
		for _, storedTx := range generatedStoredTxs {
			hash := storedTx.StakingTx.TxHash()
			tx, err := s.GetTransaction(&hash)
			require.NoError(t, err)
			require.Equal(t, storedTx.StakingTx, tx.StakingTx)
			require.Equal(t, storedTx.StakerAddress, tx.StakerAddress)
			require.Equal(t, expectedIdx, tx.StoredTransactionIdx)
			expectedIdx++
		}

		storedResult, err := s.QueryStoredTransactions(stakerdb.DefaultStoredTransactionQuery())
		require.NoError(t, err)

		require.Equal(t, len(generatedStoredTxs), len(storedResult.Transactions))
		require.Equal(t, len(generatedStoredTxs), int(storedResult.Total))

		// transactions are returned in order of insertion
		for i, storedTx := range generatedStoredTxs {
			require.Equal(t, storedTx.StakingTx, storedResult.Transactions[i].StakingTx)
			require.Equal(t, storedTx.StakerAddress, storedResult.Transactions[i].StakerAddress)
		}

		// scan transactions
		i := 0
		err = s.ScanTrackedTransactions(func(tx *stakerdb.StoredTransaction) error {
			require.Equal(t, generatedStoredTxs[i].StakingTx, tx.StakingTx)
			i++
			return nil
		}, func() {})
		require.NoError(t, err)
	})
}

func TestPaginator(t *testing.T) {
	t.Parallel()
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	s := MakeTestStore(t)
	numTx := 45
	batchSize := 20

	generatedStoredTxs := genNStoredTransactions(t, r, numTx)
	for _, storedTx := range generatedStoredTxs {
		stakerAddr, err := btcutil.DecodeAddress(storedTx.StakerAddress, &chaincfg.MainNetParams)
		require.NoError(t, err)
		err = s.AddTransactionSentToBabylon(
			storedTx.StakingTx,
			stakerAddr,
		)
		require.NoError(t, err)
	}

	query := stakerdb.DefaultStoredTransactionQuery()
	query.IndexOffset = 0
	query.NumMaxTransactions = uint64(batchSize)
	storedResult1, err := s.QueryStoredTransactions(query)

	require.NoError(t, err)
	require.Equal(t, batchSize, len(storedResult1.Transactions))
	require.Equal(t, numTx, int(storedResult1.Total))

	query = stakerdb.DefaultStoredTransactionQuery()
	query.IndexOffset = uint64(batchSize)
	query.NumMaxTransactions = uint64(batchSize)
	storedResult2, err := s.QueryStoredTransactions(query)

	require.NoError(t, err)
	require.Equal(t, batchSize, len(storedResult2.Transactions))
	require.Equal(t, numTx, int(storedResult2.Total))

	query = stakerdb.DefaultStoredTransactionQuery()
	query.IndexOffset = 2 * uint64(batchSize)
	query.NumMaxTransactions = uint64(batchSize)
	storedResult3, err := s.QueryStoredTransactions(query)
	require.NoError(t, err)
	// 2 batches of 20, 1 batch of 5
	require.Equal(t, 5, len(storedResult3.Transactions))
	require.Equal(t, numTx, int(storedResult3.Total))

	var allTransactionsFromDB []stakerdb.StoredTransaction
	allTransactionsFromDB = append(allTransactionsFromDB, storedResult1.Transactions...)
	allTransactionsFromDB = append(allTransactionsFromDB, storedResult2.Transactions...)
	allTransactionsFromDB = append(allTransactionsFromDB, storedResult3.Transactions...)

	require.Equal(t, len(generatedStoredTxs), len(allTransactionsFromDB))
	for i, storedTx := range generatedStoredTxs {
		require.Equal(t, storedTx.StakingTx, allTransactionsFromDB[i].StakingTx)
		require.Equal(t, storedTx.StakerAddress, allTransactionsFromDB[i].StakerAddress)
	}
}

func FuzzTrackInputs(f *testing.F) {
	// only 3 seeds as this is pretty slow test opening/closing db
	datagen.AddRandomSeedsToFuzzer(f, 3)

	f.Fuzz(func(t *testing.T, seed int64) {
		r := rand.New(rand.NewSource(seed))
		s := MakeTestStore(t)
		numTx := 45
		// all gene

		generatedStoredTxs := genNStoredTransactions(t, r, numTx)
		for _, storedTx := range generatedStoredTxs {
			stakerAddr, err := btcutil.DecodeAddress(storedTx.StakerAddress, &chaincfg.MainNetParams)
			require.NoError(t, err)
			err = s.AddTransactionSentToBabylon(
				storedTx.StakingTx,
				stakerAddr,
			)
			require.NoError(t, err)
		}

		for _, storedTx := range generatedStoredTxs {
			// check all inputs are used
			for _, inp := range storedTx.StakingTx.TxIn {
				used, err := s.OutpointUsed(&inp.PreviousOutPoint)
				require.NoError(t, err)
				require.True(t, used)
			}
		}

		// generate few not saved transactions
		notSaved := genNStoredTransactions(t, r, 20)

		// check all input are not used
		for _, storedTx := range notSaved {
			for _, inp := range storedTx.StakingTx.TxIn {
				used, err := s.OutpointUsed(&inp.PreviousOutPoint)
				require.NoError(t, err)
				require.False(t, used)
			}
		}
	})
}

func FuzzStoringAndRemovingTxs(f *testing.F) {
	// only 3 seeds as this is pretty slow test opening/closing db
	datagen.AddRandomSeedsToFuzzer(f, 3)

	f.Fuzz(func(t *testing.T, seed int64) {
		r := rand.New(rand.NewSource(seed))
		s := MakeTestStore(t)
		maxCreatedTx := 30
		numTx := r.Intn(maxCreatedTx) + 1
		generatedStoredTxs := genNStoredTransactions(t, r, numTx)

		for _, storedTx := range generatedStoredTxs {
			stakerAddr, err := btcutil.DecodeAddress(storedTx.StakerAddress, &chaincfg.MainNetParams)
			require.NoError(t, err)
			err = s.AddTransactionSentToBabylon(
				storedTx.StakingTx,
				stakerAddr,
			)
			require.NoError(t, err)
		}
		var expectedIdx uint64 = 1
		for _, storedTx := range generatedStoredTxs {
			hash := storedTx.StakingTx.TxHash()
			tx, err := s.GetTransaction(&hash)
			require.NoError(t, err)
			require.Equal(t, storedTx.StakingTx, tx.StakingTx)
			require.Equal(t, storedTx.StakerAddress, tx.StakerAddress)
			require.Equal(t, expectedIdx, tx.StoredTransactionIdx)
			expectedIdx++
		}

		storedResult, err := s.QueryStoredTransactions(stakerdb.DefaultStoredTransactionQuery())
		require.NoError(t, err)

		require.Equal(t, len(generatedStoredTxs), len(storedResult.Transactions))
		require.Equal(t, len(generatedStoredTxs), int(storedResult.Total))

		// transactions are returned in order of insertion
		for i, storedTx := range generatedStoredTxs {
			require.Equal(t, storedTx.StakingTx, storedResult.Transactions[i].StakingTx)
			require.Equal(t, storedTx.StakerAddress, storedResult.Transactions[i].StakerAddress)
		}

		// scan transactions
		i := 0
		err = s.ScanTrackedTransactions(func(tx *stakerdb.StoredTransaction) error {
			require.Equal(t, generatedStoredTxs[i].StakingTx, tx.StakingTx)
			i++
			return nil
		}, func() {})
		require.NoError(t, err)

		txHash := storedResult.Transactions[0].StakingTx.TxHash()
		err = s.DeleteTransactionSentToBabylon(&txHash)
		require.NoError(t, err)

		storedResultAfterDel, err := s.QueryStoredTransactions(stakerdb.DefaultStoredTransactionQuery())
		require.NoError(t, err)
		require.Equal(t, len(generatedStoredTxs)-1, len(storedResultAfterDel.Transactions))
		require.Equal(t, len(generatedStoredTxs)-1, int(storedResultAfterDel.Total))
	})
}

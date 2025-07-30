package stakerdb

import (
	"fmt"

	protobufs "github.com/babylonlabs-io/btc-staker/proto"
	"github.com/lightningnetwork/lnd/kvdb"
	"google.golang.org/protobuf/proto"
)

// MigrationResult contains the results of a migration operation
type MigrationResult struct {
	ProcessedCount int
	MigratedCount  int
	SkippedCount   int
	ErrorCount     int
}

// String returns a string representation of the migration result
func (r MigrationResult) String() string {
	return fmt.Sprintf("Processed: %d, Migrated: %d, Skipped: %d, Errors: %d",
		r.ProcessedCount, r.MigratedCount, r.SkippedCount, r.ErrorCount)
}

// MigrateTrackedTransactions migrates tracked transactions from old format to new format
// This method handles the transition from the old TrackedTransaction proto format (13 fields)
// to the new simplified format (3 fields: tracked_transaction_idx, staking_transaction, staker_address)
func (c *TrackedTransactionStore) MigrateTrackedTransactions() (*MigrationResult, error) {
	result := &MigrationResult{}

	fmt.Println("Starting tracked transactions migration...")

	// Single pass migration using write transaction (allows both read and write operations)
	err := kvdb.Batch(c.db, func(tx kvdb.RwTx) error {
		bucket := tx.ReadWriteBucket(transactionBucketName)
		if bucket == nil {
			fmt.Println("No transactions bucket found - database appears to be empty")
			return nil
		}

		cursor := bucket.ReadCursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			result.ProcessedCount++

			migrationNeeded, err := c.analyzeTransaction(k, v, true)
			if err != nil {
				result.ErrorCount++
				fmt.Printf("Error analyzing transaction at key %x: %v\n", k, err)
				continue
			}

			if !migrationNeeded {
				result.SkippedCount++
				continue
			}

			// Perform actual migration
			newData, err := c.migrateTransactionData(v)
			if err != nil {
				result.ErrorCount++
				fmt.Printf("Failed to migrate transaction at key %x: %v\n", k, err)
				continue
			}

			if err := bucket.Put(k, newData); err != nil {
				return fmt.Errorf("failed to update transaction at key %x: %w", k, err)
			}

			result.MigratedCount++
			fmt.Printf("Migrated transaction at key %x\n", k)
		}
		return nil
	})

	return result, err
}

// analyzeTransaction determines if a transaction needs migration
func (c *TrackedTransactionStore) analyzeTransaction(key []byte, data []byte, verbose bool) (bool, error) {
	// Try to unmarshal as new format first
	var newTx protobufs.TrackedTransaction
	newFormatErr := proto.Unmarshal(data, &newTx)

	// If it unmarshals successfully as new format and has valid data, it's already migrated
	if newFormatErr == nil && newTx.StakerAddress != "" && len(data) < 200 {
		return false, nil // No migration needed
	}

	// If it can be unmarshaled as new format but looks like it might need migration
	if newFormatErr == nil {
		// Check if the data looks complete for new format
		if newTx.TrackedTransactionIdx > 0 && len(newTx.StakingTransaction) > 0 && newTx.StakerAddress != "" {
			return false, nil // Already in good new format
		}
		// Otherwise, it might be partially migrated or corrupted, attempt migration
		return true, nil
	}

	// Failed to unmarshal as new format, assume it's old format that needs migration
	if verbose {
		fmt.Printf("Transaction at key %x failed to unmarshal as new format, marking for migration\n", key)
	}
	return true, nil
}

// migrateTransactionData converts old format transaction data to new format
func (c *TrackedTransactionStore) migrateTransactionData(oldData []byte) ([]byte, error) {
	// Try to unmarshal as old format (using the OldTrackedTransaction from types package)
	var oldTx protobufs.OldTrackedTransaction
	if err := proto.Unmarshal(oldData, &oldTx); err != nil {
		return nil, fmt.Errorf("failed to unmarshal old transaction data: %w", err)
	}

	// Validate that we have the essential data
	if oldTx.TrackedTransactionIdx == 0 {
		return nil, fmt.Errorf("missing tracked transaction index")
	}
	if len(oldTx.StakingTransaction) == 0 {
		return nil, fmt.Errorf("missing staking transaction data")
	}
	if oldTx.StakerAddress == "" {
		return nil, fmt.Errorf("missing staker address")
	}

	// Create new format transaction with only the essential fields
	newTx := &protobufs.TrackedTransaction{
		TrackedTransactionIdx: oldTx.TrackedTransactionIdx,
		StakingTransaction:    oldTx.StakingTransaction,
		StakerAddress:         oldTx.StakerAddress,
	}

	// Marshal to new format
	newData, err := proto.Marshal(newTx)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal new transaction format: %w", err)
	}

	return newData, nil
}

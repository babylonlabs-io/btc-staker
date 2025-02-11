package stakerdb

import "errors"

var (
	// ErrCorruptedTransactionsDB For some reason, db on disk representation have changed
	ErrCorruptedTransactionsDB = errors.New("transactions db is corrupted")

	// ErrTransactionNotFound The transaction we try update is not found in db
	ErrTransactionNotFound = errors.New("transaction not found")

	// ErrDuplicateTransaction The transaction we try to add already exists in db
	ErrDuplicateTransaction = errors.New("transaction already exists")

	// ErrInvalidUnbondingDataUpdate The unbonding data we try to update is not valid
	ErrInvalidUnbondingDataUpdate = errors.New("invalid unbonding data update")

	// ErrUnbondingDataNotFound The unbonding data we try to update is not found
	ErrUnbondingDataNotFound = errors.New("unbonding transaction data not found")
)

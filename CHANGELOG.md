<!--
Guiding Principles:

Changelogs are for humans, not machines.
There should be an entry for every single version.
The same types of changes should be grouped.
Versions and sections should be linkable.
The latest version comes first.
The release date of each version is displayed.
Mention whether you follow Semantic Versioning.

Usage:

Change log entries are to be added to the Unreleased section under the
appropriate stanza (see below). Each entry should have following format:

* [#PullRequestNumber](PullRequestLink) message

Types of changes (Stanzas):

"Features" for new features.
"Improvements" for changes in existing functionality.
"Deprecated" for soon-to-be removed features.
"Bug Fixes" for any bug fixes.
"Client Breaking" for breaking CLI commands and REST routes used by end-users.
"API Breaking" for breaking exported APIs used by developers building on SDK.
Ref: https://keepachangelog.com/en/1.0.0/
-->

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

## Unreleased

## v0.15.1

### Bug fixes

- [#122](https://github.com/babylonlabs-io/btc-staker/pull/122) Force usage of
`btcd` v0.24.2 in `go.mod`

## v0.15.0

### Improvements
- [#111](https://github.com/babylonlabs-io/btc-staker/pull/111) Add CLI command
to create phase-1/phase-2 PoP payload
- [#115](https://github.com/babylonlabs-io/btc-staker/pull/115) Add CLI command
to create payload for phase-1/phase-2 PoP deletion
- [#116](https://github.com/babylonlabs-io/btc-staker/pull/116) Add CLI command
to sign Cosmos ADR-36 messages
- [#118](https://github.com/babylonlabs-io/btc-staker/pull/118) Add CLI command
to validate PoP JSON file
- [#119](https://github.com/babylonlabs-io/btc-staker/pull/119) Bump Babylon version
to v1.0.0-rc.4

## v0.14.0

* [#108](https://github.com/babylonlabs-io/btc-staker/pull/108) Bump babylon to v1.0.0-rc.1

## v0.13.0

* [#102](https://github.com/babylonlabs-io/btc-staker/pull/102) Bump babylon v18
and fix incompatibilities

## v0.12.0

### Improvements

* [#90](https://github.com/babylonlabs-io/btc-staker/pull/90) Add CLI to create
babylon BTC delegation from phase-1 BTC staking transaction.
* [#99](https://github.com/babylonlabs-io/btc-staker/pull/99) Bump babylon version
and adapt staker to the changes

## v0.11.0

### Improvements

* [#93](https://github.com/babylonlabs-io/btc-staker/pull/93) Fix linting config
* [#95](https://github.com/babylonlabs-io/btc-staker/pull/95) Bump babylon to v0.16
* [#96](https://github.com/babylonlabs-io/btc-staker/pull/96) Check allow list
expiration height before creating new delegations

## v0.10.0

* [#87](https://github.com/babylonlabs-io/btc-staker/pull/87) Bump babylon v15

## v0.9.0

### Bug fix

* [#78](https://github.com/babylonlabs-io/btc-staker/pull/78) Fix
`withdrawable-transactions` query bug, introduced when adding pre-approval
transactions handling

### Improvements

* [#79](https://github.com/babylonlabs-io/btc-staker/pull/79) Remove `BTCUndelegate`
message sending

## v0.8.0

### Improvements

* [#51](https://github.com/babylonlabs-io/btc-staker/pull/51) Use int64
  for satoshi amount related values.
* [#65](https://github.com/babylonlabs-io/btc-staker/pull/65) Various fixes to
pre-approval flow. Do not send signed staking transactions to Babylon.
* [#66](https://github.com/babylonlabs-io/btc-staker/pull/66) Bump babylon to
v0.13.0 as it updates BTC block heights to uint32 and function naming.
* [#67](https://github.com/babylonlabs-io/btc-staker/pull/67) Enable concurrent
sending of multiple pre-approval staking transactions.

## v0.7.2

### Bug fix

* [#57](https://github.com/babylonlabs-io/btc-staker/pull/57) Use separate go
routine to check for activation after startup

## v0.7.1

### Bug fix

- [#53](https://github.com/babylonlabs-io/btc-staker/pull/53) Use only quorum of
signatures when building unbonding transaction witness

## v0.7.0

### Api breaking

* [44](https://github.com/babylonlabs-io/btc-staker/pull/44) Implement
pre-approval flow support

### Improvements

* [#48](https://github.com/babylonlabs-io/btc-staker/pull/48) Add Github actions
  for goreleaser, changelog reminder, and backport

## v0.6.0

### Bug fixes

* [20](https://github.com/babylonlabs-io/btc-staker/pull/20) Better handling
of restarting during unbonding process

### Api breaking

* [31](https://github.com/babylonlabs-io/btc-staker/pull/31) Update Babylon
to handle new `x/btcstaking` parameters

### Improvements

* [21](https://github.com/babylonlabs-io/btc-staker/pull/21) Signing taproot
spends through psbt's
* [25](https://github.com/babylonlabs-io/btc-staker/pull/25) Handle multiple
bitcoind wallets
* [26](https://github.com/babylonlabs-io/btc-staker/pull/26) Improve phase-1
commands to check transaction


## v0.5.0

Initial Release!

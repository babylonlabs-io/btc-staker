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

## v0.18.1

### Bug Fixes

* [#220](https://github.com/babylonlabs-io/btc-staker/pull/220) fix: `unstake` doesn't work for expired staking output

### Improvements

* [#218](https://github.com/babylonlabs-io/btc-staker/pull/218) chore: bump old deps and fix gosec

## v0.18.0

### Improvements

* [#202](https://github.com/babylonlabs-io/btc-staker/pull/202) chore: bump bbn v4
* [#203](https://github.com/babylonlabs-io/btc-staker/pull/203) chore: bump babylon to `v4.0.0-rc.3`
* [#204](https://github.com/babylonlabs-io/btc-staker/pull/204) chore: bump babylon to `v4.0.0`
* [#183](https://github.com/babylonlabs-io/btc-staker/pull/183) Add github actions release workflow.

## v0.17.0

### Improvements

* [#189](https://github.com/babylonlabs-io/btc-staker/pull/189) Use signing context
 string in staker pop
* [#188](https://github.com/babylonlabs-io/btc-staker/pull/188) Add stake expansion feature
* [#190](https://github.com/babylonlabs-io/btc-staker/pull/190) Add UTXO consolidation command
* [#192](https://github.com/babylonlabs-io/btc-staker/pull/192) Add migration command for stored txs
* [#195](https://github.com/babylonlabs-io/btc-staker/pull/195) Add logs with tx details on tx signature failure

### Bug Fixes

* [#191](https://github.com/babylonlabs-io/btc-staker/pull/191) Fix stake expansion validation
* [#194](https://github.com/babylonlabs-io/btc-staker/pull/194) Use params by version query in stake expansion

## v0.16.0-rc.0

### Improvements

* [#85](https://github.com/babylonlabs-io/btc-staker/pull/85) Remove unused flags
in stakercli.
* [#114](https://github.com/babylonlabs-io/btc-staker/pull/114) **Multi-staking support**.
This PR contains a series of PRs on multi-staking support and BTC staking integration.
* [#134](https://github.com/babylonlabs-io/btc-staker/pull/134) Removal of both the watch-staking
endpoint and the post-approval flow, and reduction of state in the database.

### Bug fixes

* [#184](https://github.com/babylonlabs-io/btc-staker/pull/184) remove unnecessary check
for unstaking
* [#172](https://github.com/babylonlabs-io/btc-staker/pull/172) chore: spend stake check confirmation

## v0.15.9

### Bug fixes

* [#179](https://github.com/babylonlabs-io/btc-staker/pull/179) fix: add missing parameter to
`btc_staking_param_by_btc_height`.

## v0.15.8

### Improvements

* [#175](https://github.com/babylonlabs-io/btc-staker/pull/175) Add JSON-RPC server config parameters.

## v0.15.7

### Improvements

* [#169](https://github.com/babylonlabs-io/btc-staker/pull/169) bump babylon to v1.0.0

## v0.15.6

### Improvements

* [#166](https://github.com/babylonlabs-io/btc-staker/pull/166) Fix config for
mainnet

## v0.15.5

### Improvements

* [#157](https://github.com/babylonlabs-io/btc-staker/pull/157) Move stakerapp creation from main to stakerservice
* [#156](https://github.com/babylonlabs-io/btc-staker/pull/156) disable tls in config
* [#154](https://github.com/babylonlabs-io/btc-staker/pull/154) chore: change default max feerate

* [#155](https://github.com/babylonlabs-io/btc-staker/pull/155) Add basic auth to daemon routes.
* [#151](https://github.com/babylonlabs-io/btc-staker/pull/151) Load parameters from
babylon node instead of global parameters input file in `stake-from-phase1`.
* [#163](https://github.com/babylonlabs-io/btc-staker/pull/163) bump babylon to rc.8
* [#162](https://github.com/babylonlabs-io/btc-staker/pull/162) Update PoP BIP322 signing
to sign `bytes(bbnAddrString)` due to wallet extension compatibility.

## v0.15.4

* [#146](https://github.com/babylonlabs-io/btc-staker/pull/146) Sanity check that all transactions are standard

## v0.15.3

### Improvements

* [#142](https://github.com/babylonlabs-io/btc-staker/pull/142) Set config default
keyring backend to "file" type
* [#138](https://github.com/babylonlabs-io/btc-staker/pull/138) Adds prometheus metrics
configuration to enabled it (disabled by default).

## v0.15.2

* [#127](https://github.com/babylonlabs-io/btc-staker/pull/127) Add support for
taproot addresses bip322 signing

## v0.15.1

### Bug fixes

* [#122](https://github.com/babylonlabs-io/btc-staker/pull/122) Force usage of
`btcd` v0.24.2 in `go.mod`

## v0.15.0

### Improvements
* [#111](https://github.com/babylonlabs-io/btc-staker/pull/111) Add CLI command
to create phase-1/phase-2 PoP payload
* [#115](https://github.com/babylonlabs-io/btc-staker/pull/115) Add CLI command
to create payload for phase-1/phase-2 PoP deletion
* [#116](https://github.com/babylonlabs-io/btc-staker/pull/116) Add CLI command
to sign Cosmos ADR-36 messages
* [#118](https://github.com/babylonlabs-io/btc-staker/pull/118) Add CLI command
to validate PoP JSON file
* [#119](https://github.com/babylonlabs-io/btc-staker/pull/119) Bump Babylon version
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

* [#53](https://github.com/babylonlabs-io/btc-staker/pull/53) Use only quorum of
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

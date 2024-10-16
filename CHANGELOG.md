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

### Misc Improvements

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

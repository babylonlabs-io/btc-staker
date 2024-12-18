# Transition your stake from phase-1 to phase-2 through CLI

## Understanding the transition

The transition from phase-1 to phase-2 is a manual process that requires the 
staker to transition their stake to phase-2 of the Babylon network. 
This transition has the option of being executed through the `stakercli` binary 
and this guide will show you how to do it through the `stakercli` binary. For 
detailed information about stake eligibility 
criteria, registration requirements, and how to gain voting power and earn 
rewards in phase-2, please refer to the 
[phase-2 transition guide](https://gist.github.com/vitsalis/9ebfd19bbde310e0bf4a70e7ab15a290).
<!-- TODO: Update link -->

## Table of Contents
- [Prerequisites](#prerequisites)
- [Setup](#setup)
- [Transition your stake](#transition-your-stake)
- [Verify the transition](#verify-the-transition)

## Prerequisites

To transition your stake from phase-1 to phase-2, you need to have the 
following:
- Access to your existing Bitcoin wallet from phase-1 (needed to sign transactions 
  and prove ownership of staked funds).
- The Bitcoin block height in which your staking transaction was included, which 
  will be used in the transition command.
- A funded Babylon address, which will be used to receive the rewards from the 
  transition.
- Global parameter file as seen here https://github.com/babylonlabs-io/networks/blob/main/bbn-test-5/parameters/global-params.json 
  that were used in phase-1. This will be used in the transition command later 
  on.
- A running instance of the `stakercli` binary. Please follow the `stakercli` 
  [setup guide](../README.md#3-btc-staker-installation) to complete the setup of 
  the `stakercli` with your keys before proceeding.

## Setup 

First, you will need to dump the default configuration file. This creates a 
template configuration file that you'll customize with your specific values 
(like your Bitcoin block height that your staking transaction was included in, 
wallet credentials, and network details):

```bash
stakercli admin dump-config
```

This will create a `config.json` file in your current working directory. 
You'll need to modify this file with your specific settings before proceeding. 
Here are the key configurations:

### Bitcoin Configuration
```toml
[walletconfig]
WalletName = "btc-staker"  # Your Bitcoin wallet name
WalletPass = "your-wallet-password"  # Your wallet password

[walletrpcconfig]
Host = "127.0.0.1:19001"  # Your Bitcoin node RPC endpoint
User = "your-rpc-user"    # Your Bitcoin RPC username
Pass = "your-rpc-pass"    # Your Bitcoin RPC password

[chain]
Network = "signet"  # Bitcoin network (signet for testnet)
```

### Babylon Configuration
```toml
[babylon]
Key = "btc-staker"                    # Your Babylon key name
ChainID = "bbn-test-5"               # Babylon chain ID
RPCAddr = "http://localhost:26657"    # Babylon RPC endpoint
GRPCAddr = "https://localhost:9090"   # Babylon gRPC endpoint
AccountPrefix = "bbn"                 # Babylon address prefix
KeyringBackend = "test"              # Keyring backend type
GasPrices = "0.01ubbn"              # Minimum gas price
```

Finally, start the `btcstaker` daemon, which will manage your connections to both 
Babylon and Bitcoin nodes, monitor transactions, and handle the staking process.
Add the location for the above created `config.json` file to the command:

```bash
stakerd --configfile <config-file-path> admin start
```

## Transition your stake

Following the setup of the configuration file and starting the `btcstaker` 
daemon, you can proceed to transition your stake from Phase-1 to Phase-2 using 
the following command. We use the `global_parameters.json` file that you should 
already have created as stated in the prerequisites.

```shell
stakercli daemon stake-from-phase1 <global-parameters-file> \
    --staking-transaction-hash <your-phase1-tx-hash> \
    --staker-address <your-btc-address> \
    --tx-inclusion-height <block-height>
```

parameters:
- `global-parameters-file`: The path to the global parameters file.
- `your-phase1-tx-hash`: The original hash of your phase-1 staking transaction.
- `your-btc-address`: BTC address of the staker in hex.
- `block-height`: The block height at which your staking transaction was 
  included.

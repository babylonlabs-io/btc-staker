# Transition your stake from phase-1 to phase-2 through CLI

<!-- TODO -->


>  **⚡ Note:** This program is a separate implementation from the staker program 
>  used for Phase-1. All stakers are required to transition their stakes to this 
>  program to participate in Phase-2.

## Table of Contents
- [Prerequisites](#prerequisites)
- [1. Setup](#1-setup)
- [2. Transition your stake](#2-transition-your-stake)

## Prerequisites

To transition your stake from phase-1 to phase-2, you need to have the following:
-  Global parameter file as seen here https://github.com/babylonlabs-io/networks/blob/main/bbn-5/parameters/global-params.json that were used in phase-1
-  The Bitcoin block height in which your staking transaction was included
- Your `btc-staker` binary setup and running inclusive of the btc staker config 
  properly setup

## 1. Setup 

First, you need to run the upgrade setup which configures the environment and 
runs necessary upgrade procedures:

```bash
cd deployments/local
make bbn-upgrade-v1
```

Next, you need to dump the default configuration file. This creates a template 
that you'll customize with your specific values (like your Bitcoin block height 
that your staking transaction was included in, wallet credentials, 
and network details):

```bash
stakercli admin dump-config
```

This will create a `config.json` file in your current working directory. 
You'll need to modify this file with your specific settings before proceeding.

Finally, start the `btcstaker` daemon which will manage your connections to both 
Babylon and Bitcoin nodes, monitor transactions, and handle the staking process:

```bash
stakercli admin start
```

## 2. Transition your stake

After setting up the configuration file and starting the `btcstaker` daemon, 
you can proceed to transition your stake from Phase-1 to Phase-2 using the 
following command. We use the `global_parameters.json` file that you should 
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
- `your-btc-address`: BTC address of the staker in hex
- `block-height`: The block height at which your staking transaction was 
    included.


# Register your Phase-1 stake to Phase-2 through CLI

## Understanding the registration process

To register your Bitcoin stake on the Babylon chain, you must have a confirmed 
Bitcoin staking transaction. Before proceeding, please review the 
[Registration of Existing Stakes to the Babylon Chain](https://github.com/babylonlabs-io/babylon/blob/main/docs/stake-registration.md) 
documentation to check your eligibility and understand the registration 
requirements and process.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Setup](#setup)
- [Register your stake](#register-your-stake)
- [Verify the registration](#verify-the-registration)

## Prerequisites

To register your stake to the Babylon blockchain, the following are required:
- Access to the Bitcoin wallet you have used to create your stake on Bitcoin 
  (needed to sign transactions).
- The Bitcoin block height in which your staking transaction was included, which 
  will be used in the registration command.
- A funded Babylon address, which will be used to receive the rewards from the 
  registration.
- Global parameter file as seen here https://github.com/babylonlabs-io/networks/blob/main/bbn-test-5/parameters/global-params.json 
  that were used when you created your Bitcoin stake. This will be used in the 
  registration command later on.
- A running instance of the `stakerd` daemon. Please follow the `stakerd` 
  [setup guide](../README.md#3-btc-staker-installation) to complete the setup. 
  This is also inclusive of creating a Babylon keyring with funds step as the 
  `stakerd` daemon requires a funded keyring to pay for the transactions.

## Setup and configuration

> **⚡ Note**: While the `stakerd` daemon is already running, it needs access to 
> the Bitcoin wallet containing your staking transaction's private key. This 
> setup ensures the daemon can interact with the correct Bitcoin wallet.

To get started, you will need to create a configuration file. You can do this 
by running the `dump-config` command. This will create a `config.json` file 
in your current working directory that you'll customize with your specific 
values:

```bash
stakercli admin dump-config
```

The configuration file below contains default settings and placeholders 
for your Bitcoin and Babylon values. Please replace the placeholders with 
your specific information:

```toml
[walletconfig]
WalletName = "btc-staker"  # Replace with your Bitcoin wallet name
WalletPass = "your-wallet-password"  # Replace with your wallet password

[walletrpcconfig]
Host = "127.0.0.1:19001"  # Bitcoin Wallet RPC endpoint
User = "your-rpc-user"    # Replace with your Bitcoin RPC username
Pass = "your-rpc-pass"    # Replace with your Bitcoin RPC password

[chain]
Network = "signet"  # Bitcoin network (signet for testnet)
```

Finally, start the `btcstaker` daemon, which will manage your connections to both 
Babylon and Bitcoin nodes, monitor transactions, and handle the staking process.
Add the location for the above created `config.json` file to the command:

```shell
stakerd --configfile <config-file-path> admin start
```

## Register your stake

After configuring and starting the `btcstaker` daemon, you'll need the 
`global_parameters.json` file (created during prerequisites) for the next steps.

A few notes about the `global-parameters.json` file:
1. It is used to retrieve covenant keys and quorum from the parameters version 
   you staked in.
2. It can also be used to parse your Bitcoin staking transaction to extract 
   important information from the `OP_RETURN` data, which contains:
   - The staking period you chose
   - The finality provider you chose

> **⚡ Note**: While these parameters can be provided manually, the global 
> parameters file provides an easier user experience. This guide is only for 
> valid, confirmed Bitcoin staking transactions with valid `OP_RETURN` data. If 
> your transaction has malformed `OP_RETURN` data or isn't a confirmed staking 
> transaction, to check your eligibility please refer to the 
> [registration eligibility guide](registration-eligibility.md).

Now that you have the `global-parameters.json` file, you can register your 
Bitcoin stake by running the following command:

```shell
stakercli daemon stake-from-phase1 <global-parameters-file> \
    --staking-transaction-hash <your-phase1-tx-hash> \
    --staker-address <your-btc-address> \
    --tx-inclusion-height <block-height>
```

parameters:
- `global-parameters-file`: The path to the global parameters file.
- `your-phase1-tx-hash`: The original hash of your Bitcoin staking transaction.
- `your-btc-address`: BTC address of the staker in hex.
- `block-height`: The BTC block height at which your staking transaction was 
  included.

The above command will output a transaction hash similar to below 
that you can use to verify the registration on the Babylon blockchain, which  
you will see in the next section.

```json
{
  "babylon_btc_delegation_tx_hash": "<btc-delegation-tx-hash>"
}
```

## Verify your registration

Following the registration of your Bitcoin stake, you can verify your 
registration by checking your balance on the [Babylon Explorer](https://babylon-testnet.l2scan.co) 
by searching for the `<babylon_btc_delegation_tx_hash>` value.

This will then give you details on your transaction, which includes the state 
of the transaction, which can be one of the following:

- `SENT_TO_BTC` - Initial state
- `CONFIRMED_ON_BTC` - Bitcoin confirmation
- `SENT_TO_BABYLON` - Registration submitted to Babylon
- `VERIFIED` - Registration verified
- `DELEGATION_ACTIVE` - Stake active and has voting power
- `UNBONDING_CONFIRMED_ON_BTC` - Unbonding in progress
- `SPENT_ON_BTC` - Stake withdrawn

Depending on the state of the transaction, you can see the progress of the 
registration on the Babylon blockchain, as it will take a few minutes for the 
transaction to be verified and the stake to be active.

## Receiving rewards

Following registration, rewards will be accrued to your Babylon address 
(configured in `stakerd`).

> **⚠️ Important**: While rewards are accumulating to your Babylon address, 
> withdrawals are not yet available. You will be able to access your rewards 
> once the claiming feature is implemented.

To monitor your rewards, you can use the [Babylon Explorer](https://babylon-testnet.l2scan.co) 
to check your balance on the Babylon blockchain using your Babylon address.

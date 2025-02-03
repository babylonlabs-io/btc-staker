# Register your Phase-1 stake to Phase-2 through CLI

## Understanding the registration process

To register your Bitcoin stake on the Babylon chain, you must have a confirmed 
Bitcoin staking transaction. Before proceeding, please review the 
[Registration of Existing Stakes to the Babylon Chain](https://github.com/babylonlabs-io/babylon/blob/main/docs/stake-registration.md) 
documentation to check your eligibility and understand the registration 
requirements and process.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Register your stake](#register-your-stake)
- [Verify your registration](#verify-your-registration)

## Prerequisites

- **Staker Daemon**: A running instance of the `stakerd` daemon.
  - **Bitcoin Wallet**: The `stakerd` daemon should connect and have access to 
    the Bitcoin wallet that you have previously used to create your Bitcoin 
    stake. This will be needed to create a proof of ownership of the stake. 
  - **Funded Babylon Account**: The `stakerd` daemon should have access to a 
    funded Babylon account. This account will pay for transaction fees for 
    the interaction with the Babylon blockchain, as well as be used as the 
    recipient for BTC staking rewards in the respective native PoS token 
    (note: testnet tokens have no value).
  - **Setup Guide**: The  `stakerd`
    [setup guide](../README.md#3-btc-staker-installation) contains all details 
    on how to set up the `stakerd` and connect it with your Bitcoin wallet 
    and Babylon account.
- **Phase-1 Parameters**: The staker CLI requires the parameters that were used 
  when creating the phase-1 staking transaction in order to construct a valid 
  Babylon chain registration transaction.
  Specifically, it requires the following:
  - **Global Parameter Versions**: The global parameters file containing the full 
    parameters versions for the phase-1 network you submitted your stake in 
    (e.g.,[testnet parameters](https://github.com/babylonlabs-io/networks/blob/main/bbn-test-4/parameters/global-params.json)).
  - **Bitcoin Inclusion Height**: The Bitcoin block height in which your staking 
    transaction was included, which will be used in the registration command. 
    You can find this through Bitcoin explorer tools such as 
    [mempool.space](https://mempool.space).

## Register your stake

After configuring and starting the `stakerd` daemon, you'll need the 
`global_parameters.json` file (created during prerequisites) for the next steps.

A few notes about the `global-parameters.json` file:
1. It is used to retrieve covenant keys and quorum from the parameters version 
   you staked in.
2. It can also be used to parse your Bitcoin staking transaction to extract 
   important information from the `OP_RETURN` data, which contains:
   - The staking period you chose
   - The finality provider you chose

> **⚡ Note**: While these parameters can be provided manually, the global 
> parameters file provides a smoother user experience. This guide is only for 
> valid Bitcoin staking transactions with well-formed `OP_RETURN` data that 
> have received sufficient Bitcoin confirmations (e.g., 10 for testnet). If  
> your transaction has malformed `OP_RETURN` data or isn't a confirmed staking 
> transaction (because it is a new one or very recently submitted), it cannot be 
> registered.
> To check your eligibility please refer to the 
> [registration eligibility guide](https://github.com/babylonlabs-io/babylon/blob/main/docs/stake-registration.md).

Now that you have the `global-parameters.json` file, you can register your 
Bitcoin stake by running the following command:

```shell
stakercli daemon stake-from-phase1 <global-parameters-file> \
    --staking-transaction-hash <your-phase1-tx-hash> \
    --staker-address <your-btc-address> \
    --tx-inclusion-height <block-height>
```

Parameters:
- `global-parameters-file`: The path to the global parameters file.
- `your-phase1-tx-hash`: The original hash of your Bitcoin staking transaction.
  This will be used to retrieve the staking transaction from your wallet.
- `your-btc-address`: BTC address of the staker (bech32 format). For example, 
  `tb1q9hr5zxsvtzg3gxpewdc7ft9yam2c6cfeaz75jj`.
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

## Verify Your Registration

After submitting your stake registration with `stake-from-phase1`, you can 
verify your registration with either of the following methods:

1. Check your stake's local tracking status in `stakerd`:

```shell
# View all stakes being tracked:
stakercli daemon list-staking-transactions

# Or check a specific transaction:
stakercli daemon staking-details --staking-transaction-hash <your-btc-tx-hash>
```

The response will show an output similar to below:

```json
{
    "staking_tx_hash": "<your-btc-tx-hash>",
    "staker_address": "<btc-staker-address>",
    "staking_state": "SENT_TO_BABYLON",
    "watched": true,
    "transaction_idx": "1"
}
```
As you can see, the `staking_state` field will show the current state of your 
stake registration. Your stake will progress through these states:

- `SENT_TO_BTC` - Initial state when transaction is created
- `CONFIRMED_ON_BTC` - Bitcoin network has confirmed the transaction
- `SENT_TO_BABYLON` - Registration submitted to Babylon chain
- `VERIFIED` - Covenant signatures received
- `DELEGATION_ACTIVE` - Stake is active with voting power
- `UNBONDING_CONFIRMED_ON_BTC` - Unbonding in progress
- `SPENT_ON_BTC` - Stake has been withdrawn

Once your staking state reaches `DELEGATION_ACTIVE`, your stake is active and 
participating in the network.

If you wish to check your registration on the Babylon chain, you can then 
verify your registration with the next step.

2. Babylon Chain Status:

```shell
# From your stake-from-phase1 response:
{
  "babylon_btc_delegation_tx_hash": "<btc-delegation-tx-hash>"
}

# View on Babylon Explorer:
https://babylon-testnet.l2scan.co/tx/<btc-delegation-tx-hash>
```
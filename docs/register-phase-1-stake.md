# Register your Phase-1 stake to Phase-2 through CLI

## Understanding the registration process

To register your Bitcoin stake on the Babylon chain, you must have a confirmed 
Bitcoin staking transaction. Before proceeding, please review the 
[Registration of Existing Stakes to the Babylon Chain](https://github.com/babylonlabs-io/babylon/blob/main/docs/stake-registration.md) 
documentation to check your eligibility and understand the registration 
requirements and process.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Setup and configuration](#setup-and-configuration)
- [Register your stake](#register-your-stake)
- [Verify your registration](#verify-your-registration)
- [Receiving rewards](#receiving-rewards)

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
> [registration eligibility guide](registration-eligibility.md).

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

The below states relate to the statuses maintained by stakerd. Above you refer 
to going to the Babylon explorer. Something is missing here I think. In general, I recommend that we check the status of the transaction by stakerd/stakercli commands instead of sending people to a 3rd party explorer.

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

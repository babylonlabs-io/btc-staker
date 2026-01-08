# Multisig test flow (dev/QA)

Multisig support lives on dedicated commands so you can keep single-sig and multisig runs isolated. A full demo sequence is in [`babylon-deployment/deployments/btcstaking-bitcoind/btcstaking-demo.sh`](https://github.com/babylonlabs-io/babylon-deployment/blob/main/deployments/btcstaking-bitcoind/btcstaking-demo.sh).

## Getting multisig WIFs with `bitcoin-cli` (regtest)
If you want to generate WIFs with `bitcoin-cli` (as done in `babylon-deployment/contrib/images/bitcoindsim/wrapper.sh`):
- Create/load a wallet:
  ```bash
  bitcoin-cli -regtest -rpcuser=<user> -rpcpassword=<pass> createwallet btcstaker-multisig
  ```
- Generate addresses and dump their WIFs:
  ```bash
  addr=$(bitcoin-cli -regtest -rpcuser=<user> -rpcpassword=<pass> -rpcwallet=btcstaker-multisig getnewaddress)
  wif=$(bitcoin-cli -regtest -rpcuser=<user> -rpcpassword=<pass> -rpcwallet=btcstaker-multisig dumpprivkey "$addr")
  echo "$addr $wif"
  ```
  Repeat to collect as many WIFs as needed, then set them into `StakerKeyWIFs` (comma-separated) and set `StakerThreshold` in `stakerd.conf`.

## Configure multisig staker keys
- In `stakerd.conf`, add a `[stakermultisigconfig]` section with a comma-separated list of WIFs and a quorum:
  ```ini
  [stakermultisigconfig]
  StakerKeyWIFs = cMnvZ2rhpchH3BVAirJxfyqHqCo9Mmhxg1crw27MCqmyUsC19hHK,cQLpF5ABfQUZmvKFRApfUGCyjAV9sJJG77xDrCKpa6NTkHYG9ygB,cRk2zgVCNc9s23ru62PebkQQxuPio9BwzSuz2hMHBStYrvuczoXC
  StakerThreshold = 2
  ```
  Keys are sorted internally by x-only pubkey; no need to pre-sort.

## Commands (require `stakerd` running)
- Stake with multisig keys (funding UTXO comes from the wallet-controlled funding address you pass):
  ```bash
  stakercli dn stake-multisig \
    --funding-address <wallet-bech32> \
    --staking-amount <sats> \
    --finality-providers-pks <fp_pk_hex>[,<fp_pk_hex>...] \
    --staking-time <blocks>
  ```
- Unbond and spend (multisig):
  ```bash
  stakercli dn unbond-multisig --staking-transaction-hash <txid>
  stakercli dn unstake-multisig --staking-transaction-hash <txid>
  ```
- Stake expansion with multisig keys (previous active staking tx + wallet funding input):
  ```bash
  stakercli dn stake-expand-multisig \
    --funding-address <wallet-bech32> \
    --staking-amount <sats> \
    --finality-providers-pks <fp_pk_hex>[,<fp_pk_hex>...] \
    --staking-time <blocks> \
    --staking-transaction-hash <prev_staking_txid>
  ```

## Notes
- PoP and slashing/unbonding signatures are produced locally from the multisig keys; **a single-sig wallet is still required for funding/change UTXOs**. 
  The funding address you pass must belong to that wallet, and its UTXOs are consumed even in multisig flows.
- Witness ordering follows Babylon rules: staker pubkeys sorted lexicographically; witness stack is reverse-lex with blanks after quorum.
- For a working example with timings, mirror the sequence in `multisig-demo.sh` at **babylon-deployment** repo (three multisig delegations, one expansion, unbond/unstake).

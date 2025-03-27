extern crate bitcoin;
extern crate bitcoin_wallet;

use bitcoin::network::constants::Network;
use bitcoin::util::address::Address;
use bitcoin::util::amount::Amount;
use bitcoin_wallet::account::{Account, MasterAccount};
use bitcoin_wallet::mnemonic::Mnemonic;
use bitcoin_wallet::wallet::Wallet;

fn main() {
    // Target wallet address from PR description
    let target_address = "1N82hX1rYDHjF6uzTGFpC9yhZzD4N9ky9b";

    // Create a new wallet using a proper BIP-39 mnemonic phrase
    let mnemonic = Mnemonic::from_str("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
    let master_account = MasterAccount::from_mnemonic(&mnemonic, 0, Network::Bitcoin).unwrap();
    let account = master_account.get_account(0).unwrap();

    // Amount to send
    let amount = Amount::from_btc(1.0).unwrap();

    // Create the transaction
    let mut tx_builder = account.create_tx_builder();
    tx_builder.add_recipient(Address::from_str(target_address).unwrap(), amount.as_sat());

    // Sign the transaction
    let tx = tx_builder.finalize().unwrap();

    // Send the transaction
    account.send_tx(&tx).unwrap();

    println!("1 Bitcoin sent to address: {}", target_address);
}

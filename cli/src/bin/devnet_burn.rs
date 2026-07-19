//! Burn pDOGE (request_withdrawal) + snapshot_withdrawals on Solana devnet

use doge_bridge_client::instructions;
use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signer::keypair::read_keypair_file;
use solana_sdk::signer::Signer;
use solana_sdk::transaction::Transaction;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let rpc_url = args.get(1).cloned().unwrap_or_else(|| "https://api.devnet.solana.com".to_string());
    let payer_path = args.get(2).cloned().unwrap_or_else(|| "bridge-config/keys/payer.json".to_string());
    let operator_path = args.get(3).cloned().unwrap_or_else(|| "bridge-config/keys/operator.json".to_string());

    println!("=== Devnet Burn + Snapshot ===");
    let payer = read_keypair_file(&payer_path).expect("read payer");
    let operator = read_keypair_file(&operator_path).expect("read operator");
    println!("Payer: {}", payer.pubkey());
    println!("Operator: {}", operator.pubkey());

    let rpc = RpcClient::new(&rpc_url);
    let program_id = Pubkey::from_str_const("9HdfoY6yYFLo3sQ5qMv9tHHgXzB3AnA2GXXyedeWrLdN");
    let doge_mint = Pubkey::from_str_const("2nNioXNrhdrMkbTBaqp21mmaKDVtiooSyHapdMcoJNKN");
    let user_ata = Pubkey::from_str_const("E2TK98AKb3AanyLmbJziK7pwx6vNfxX9UzAnf6oMmPUY");

    // Recipient: mzpA3kNXzAczvzWWwxXwF5AvoE3nUbaxGK (P2PKH, hash160 from scriptPubKey)
    let recipient_address: [u8; 20] = [
        0xd3, 0xab, 0x45, 0xbf, 0x32, 0x06, 0xdd, 0x06,
        0xba, 0xd9, 0x6a, 0xfa, 0x8c, 0x3e, 0xbb, 0x20,
        0x05, 0x51, 0xb9, 0xd4,
    ];
    let amount_sats: u64 = 500_000_000; // 5 DOGE
    let address_type: u32 = 0; // P2PKH

    // Step 1: Request withdrawal (burn pDOGE)
    println!("\n=== Step 1: request_withdrawal (burn 5 pDOGE) ===");
    let burn_ix = instructions::request_withdrawal(
        program_id,
        payer.pubkey(),
        doge_mint,
        user_ata,
        recipient_address,
        amount_sats,
        address_type,
    );
    let blockhash = rpc.get_latest_blockhash().expect("blockhash");
    let tx = Transaction::new_signed_with_payer(
        &[burn_ix], Some(&payer.pubkey()), &[&payer], blockhash);
    match rpc.send_and_confirm_transaction(&tx) {
        Ok(sig) => println!("✅ Burn: {}", sig),
        Err(e) => {
            eprintln!("❌ Burn: {}", e);
            return;
        }
    }

    let snapshot_ix = instructions::snapshot_withdrawals(
        program_id, operator.pubkey(), payer.pubkey(),
    );
    let blockhash = rpc.get_latest_blockhash().expect("blockhash");
    let tx = Transaction::new_signed_with_payer(
        &[snapshot_ix], Some(&payer.pubkey()), &[&payer, &operator], blockhash);
    match rpc.send_and_confirm_transaction(&tx) {
        Ok(sig) => println!("✅ Snapshot: {}", sig),
        Err(e) => eprintln!("❌ Snapshot: {}", e),
    }

    // Check pDOGE balance after burn
    println!("\n=== pDOGE balance after burn ===");
    match rpc.get_token_account_balance(&user_ata) {
        Ok(bal) => println!("Balance: {} pDOGE", bal.ui_amount_string),
        Err(e) => eprintln!("Error: {}", e),
    }
}
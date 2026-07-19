//! Deposit flow on Solana devnet: insert pending mint → block_update → mint pDOGE

use doge_bridge_client::instructions;
use psy_bridge_core::crypto::zk::CompactBridgeZKProof;
use psy_bridge_core::header::PsyBridgeHeader;
use solana_client::rpc_client::RpcClient;
use solana_sdk::compute_budget::ComputeBudgetInstruction;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signer::keypair::read_keypair_file;
use solana_sdk::signer::Signer;
use solana_sdk::transaction::Transaction;
use std::{env, fs};

fn main() {
    let args: Vec<String> = env::args().collect();
    let rpc_url = args.get(1).cloned().unwrap_or_else(|| "https://api.devnet.solana.com".to_string());
    let payer_path = args.get(2).cloned().unwrap_or_else(|| "bridge-config/keys/payer.json".to_string());
    let operator_path = args.get(3).cloned().unwrap_or_else(|| "bridge-config/keys/operator.json".to_string());
    let proof_path = args.get(4).cloned().unwrap_or_else(|| "/tmp/bridge-block-transition-proof.bin".to_string());
    let header_path = args.get(5).cloned().unwrap_or_else(|| "/tmp/new_header_deposit_320.bin".to_string());
    let mint_data_path = args.get(6).cloned().unwrap_or_else(|| "/tmp/pending_mint_data.bin".to_string());

    println!("=== Devnet Deposit Flow ===");
    let payer = read_keypair_file(&payer_path).expect("read payer");
    let operator = read_keypair_file(&operator_path).expect("read operator");
    println!("Payer: {}", payer.pubkey());
    println!("Operator: {}", operator.pubkey());

    let rpc = RpcClient::new(&rpc_url);

    let program_id = Pubkey::from_str_const("9HdfoY6yYFLo3sQ5qMv9tHHgXzB3AnA2GXXyedeWrLdN");
    let pending_mint_id = Pubkey::from_str_const("DHB58D8HbnRM7QQiJ37iE3YjCfUbzbhpcc2Bf5rAXkua");
    let txo_buffer_id = Pubkey::from_str_const("9N217cCfEhickevyD3amY1BQh8P8Hay7CKKWa5kgrgHs");
    // pDOGE mint from initialization
    let doge_mint = Pubkey::from_str_const("2nNioXNrhdrMkbTBaqp21mmaKDVtiooSyHapdMcoJNKN");

    let operator_bytes = operator.pubkey().to_bytes();
    let (bridge_state, _) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);
    let (mint_buffer, mint_bump) = Pubkey::find_program_address(
        &[b"mint_buffer", &operator_bytes], &pending_mint_id);
    let (txo_buffer, txo_bump) = Pubkey::find_program_address(
        &[b"txo_buffer", &operator_bytes], &txo_buffer_id);

    // Recipient ATA: payer's ATA for pDOGE
    let recipient = payer.pubkey();
    let recipient_ata = spl_associated_token_account::get_associated_token_address(
        &recipient, &doge_mint);

    println!("Bridge state: {}", bridge_state);
    println!("Mint buffer: {}", mint_buffer);
    println!("pDOGE mint: {}", doge_mint);
    println!("Recipient: {}", recipient);
    println!("Recipient ATA: {}", recipient_ata);

    // Step 0: Create recipient ATA if it doesn't exist
    println!("\n=== Step 0: Create recipient ATA ===");
    if rpc.get_account(&recipient_ata).is_err() {
        println!("Creating ATA...");
        let create_ata_ix = spl_associated_token_account::create_associated_token_account(
            &payer.pubkey(), &recipient, &doge_mint);
        let blockhash = rpc.get_latest_blockhash().expect("blockhash");
        let tx = Transaction::new_signed_with_payer(
            &[create_ata_ix], Some(&payer.pubkey()), &[&payer], blockhash);
        match rpc.send_and_confirm_transaction(&tx) {
            Ok(sig) => println!("✅ ATA created: {}", sig),
            Err(e) => eprintln!("❌ ATA: {}", e),
        }
    } else {
        println!("ATA already exists");
    }

    // Step 1: Reinit pending-mint-buffer with 1 mint
    println!("\n=== Step 1: Reinit mint buffer (1 mint) ===");
    let reinit_ix = instructions::pending_mint_reinit(
        pending_mint_id, mint_buffer, operator.pubkey(), 1);
    let blockhash = rpc.get_latest_blockhash().expect("blockhash");
    let tx = Transaction::new_signed_with_payer(
        &[reinit_ix], Some(&payer.pubkey()), &[&payer, &operator], blockhash);
    match rpc.send_and_confirm_transaction(&tx) {
        Ok(sig) => println!("✅ Reinit: {}", sig),
        Err(e) => eprintln!("❌ Reinit: {}", e),
    }

    // Step 2: Insert PendingMint data into group 0
    println!("\n=== Step 2: Insert mint data ===");
    let mint_data = fs::read(&mint_data_path).expect("read mint data");
    println!("Mint data: {} bytes", mint_data.len());
    let insert_ix = instructions::pending_mint_insert(
        pending_mint_id, mint_buffer, operator.pubkey(), 0, &mint_data);
    let blockhash = rpc.get_latest_blockhash().expect("blockhash");
    let tx = Transaction::new_signed_with_payer(
        &[insert_ix], Some(&payer.pubkey()), &[&payer, &operator], blockhash);
    match rpc.send_and_confirm_transaction(&tx) {
        Ok(sig) => println!("✅ Insert: {}", sig),
        Err(e) => eprintln!("❌ Insert: {}", e),
    }

    // Step 3: Submit block_update with deposit proof
    println!("\n=== Step 3: block_update ===");
    let proof_bytes = fs::read(&proof_path).expect("read proof");
    println!("Proof: {} bytes", proof_bytes.len());
    let proof_arr: [u8; 356] = proof_bytes.as_slice().try_into().expect("356 bytes");
    let proof: CompactBridgeZKProof = proof_arr;

    let header_bytes = fs::read(&header_path).expect("read header");
    assert_eq!(header_bytes.len(), 320);
    let header: &PsyBridgeHeader = bytemuck::from_bytes(&header_bytes);

    let cu_ix = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let block_ix = instructions::block_update(
        program_id, payer.pubkey(), proof, *header,
        operator.pubkey(), mint_buffer, txo_buffer, mint_bump, txo_bump);

    let blockhash = rpc.get_latest_blockhash().expect("blockhash");
    let tx = Transaction::new_signed_with_payer(
        &[cu_ix, block_ix], Some(&payer.pubkey()), &[&payer, &operator], blockhash);
    println!("Submitting block_update...");
    match rpc.send_and_confirm_transaction(&tx) {
        Ok(sig) => println!("✅ block_update: {}", sig),
        Err(e) => eprintln!("❌ block_update: {}", e),
    }

    // Step 4: Process mint group to mint pDOGE
    println!("\n=== Step 4: process_mint_group ===");
    let mint_ix = instructions::process_mint_group(
        program_id, operator.pubkey(), mint_buffer, doge_mint,
        vec![recipient_ata], 0, mint_bump, true);
    let cu_ix2 = ComputeBudgetInstruction::set_compute_unit_limit(200_000);
    let blockhash = rpc.get_latest_blockhash().expect("blockhash");
    let tx = Transaction::new_signed_with_payer(
        &[cu_ix2, mint_ix], Some(&payer.pubkey()), &[&payer, &operator], blockhash);
    println!("Submitting process_mint_group...");
    match rpc.send_and_confirm_transaction(&tx) {
        Ok(sig) => println!("✅ process_mint_group: {}", sig),
        Err(e) => eprintln!("❌ process_mint_group: {}", e),
    }

    // Check pDOGE balance
    println!("\n=== Check pDOGE balance ===");
    match rpc.get_token_account(&recipient_ata) {
        Ok(Some(acct)) => println!("✅ pDOGE balance: {} (decimals: {})",
            acct.token_amount.amount, acct.token_amount.decimals),
        Ok(None) => println!("❌ Token account not found"),
        Err(e) => eprintln!("❌ Error: {}", e),
    }
}
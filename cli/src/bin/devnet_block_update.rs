//! Submit a block_update to Solana devnet with a pre-generated SP1 proof.
//! First creates pending-mint-buffer and txo-buffer accounts if needed.

use doge_bridge_client::instructions;
use psy_bridge_core::crypto::zk::CompactBridgeZKProof;
use psy_bridge_core::header::PsyBridgeHeader;
use solana_sdk::compute_budget::ComputeBudgetInstruction;
use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signer::keypair::read_keypair_file;
use solana_sdk::signer::Signer;
use solana_sdk::system_instruction;
use solana_sdk::transaction::Transaction;
use std::{env, fs};

fn main() {
    let args: Vec<String> = env::args().collect();
    let rpc_url = args.get(1).cloned().unwrap_or_else(|| "https://api.devnet.solana.com".to_string());
    let payer_path = args.get(2).cloned().unwrap_or_else(|| "bridge-config/keys/payer.json".to_string());
    let operator_path = args.get(3).cloned().unwrap_or_else(|| "bridge-config/keys/operator.json".to_string());
    let proof_path = args.get(4).cloned().unwrap_or_else(|| "/tmp/bridge-block-transition-proof.bin".to_string());
    let header_path = args.get(5).cloned().unwrap_or_else(|| "/tmp/new_header_320.bin".to_string());

    println!("=== Devnet Block Update ===");
    let payer = read_keypair_file(&payer_path).expect("read payer");
    let operator = read_keypair_file(&operator_path).expect("read operator");
    println!("Payer: {}", payer.pubkey());
    println!("Operator: {}", operator.pubkey());

    let rpc = RpcClient::new(&rpc_url);

    let program_id = Pubkey::from_str_const("DBjo5tqf2uwt4sg9JznSk9SBbEvsLixknN58y3trwCxJ");
    let pending_mint_id = Pubkey::from_str_const("PMUSqycT1j5JTLmHk8frGSCido2h9VG1pyh2MPEa33o");
    let txo_buffer_id = Pubkey::from_str_const("TXWhjswto9q6hfaGPuAhDS79wAHKfbMJLVR178xYAaQ");

    let operator_bytes = operator.pubkey().to_bytes();
    let (bridge_state, _) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);
    let (mint_buffer, mint_bump) = Pubkey::find_program_address(
        &[b"mint_buffer", &operator_bytes], &pending_mint_id);
    let (txo_buffer, txo_bump) = Pubkey::find_program_address(
        &[b"txo_buffer", &operator_bytes], &txo_buffer_id);

    println!("Bridge state: {}", bridge_state);
    println!("Mint buffer: {} (bump {})", mint_buffer, mint_bump);
    println!("TXO buffer: {} (bump {})", txo_buffer, txo_bump);

    // Step 1: Create pending-mint-buffer (only payer signs)
    println!("\n=== Step 1: Create pending-mint-buffer ===");
    if rpc.get_account(&mint_buffer).is_err() {
        let space = 72;
        let rent = rpc.get_minimum_balance_for_rent_exemption(space).expect("rent");
        let transfer_ix = system_instruction::transfer(&payer.pubkey(), &mint_buffer, rent);
        let setup_ix = instructions::pending_mint_setup(
            pending_mint_id, mint_buffer, bridge_state, operator.pubkey());
        let blockhash = rpc.get_latest_blockhash().expect("blockhash");
        let tx = Transaction::new_signed_with_payer(
            &[transfer_ix, setup_ix], Some(&payer.pubkey()), &[&payer], blockhash);
        match rpc.send_and_confirm_transaction(&tx) {
            Ok(sig) => println!("✅ Mint buffer created: {}", sig),
            Err(e) => eprintln!("❌ Failed: {}", e),
        }
    } else { println!("Already exists"); }

    // Step 2: Create txo-buffer (only payer signs)
    println!("\n=== Step 2: Create txo-buffer ===");
    if rpc.get_account(&txo_buffer).is_err() {
        let space = 72;
        let rent = rpc.get_minimum_balance_for_rent_exemption(space).expect("rent");
        let transfer_ix = system_instruction::transfer(&payer.pubkey(), &txo_buffer, rent);
        let init_ix = instructions::txo_buffer_init(txo_buffer_id, txo_buffer, operator.pubkey());
        let blockhash = rpc.get_latest_blockhash().expect("blockhash");
        let tx = Transaction::new_signed_with_payer(
            &[transfer_ix, init_ix], Some(&payer.pubkey()), &[&payer], blockhash);
        match rpc.send_and_confirm_transaction(&tx) {
            Ok(sig) => println!("✅ TXO buffer created: {}", sig),
            Err(e) => eprintln!("❌ Failed: {}", e),
        }
    } else { println!("Already exists"); }

    // Step 3: Reinit pending-mint-buffer with 0 mints (payer pays gas, operator signs)
    println!("\n=== Step 3: Reinit mint buffer (0 mints) ===");
    let reinit_ix = instructions::pending_mint_reinit(
        pending_mint_id, mint_buffer, operator.pubkey(), 0);
    let blockhash = rpc.get_latest_blockhash().expect("blockhash");
    let tx = Transaction::new_signed_with_payer(
        &[reinit_ix], Some(&payer.pubkey()), &[&payer, &operator], blockhash);
    match rpc.send_and_confirm_transaction(&tx) {
        Ok(sig) => println!("✅ Reinit: {}", sig),
        Err(e) => eprintln!("❌ Reinit failed: {}", e),
    }

    // Step 4: Submit block_update (payer + operator sign)
    println!("\n=== Step 4: Submit block_update ===");
    let proof_bytes = fs::read(&proof_path).expect("read proof");
    println!("Proof: {} bytes", proof_bytes.len());
    let proof_arr: [u8; 356] = proof_bytes.as_slice().try_into().expect("356 bytes");
    let proof: CompactBridgeZKProof = proof_arr;

    let header_bytes = fs::read(&header_path).expect("read header");
    assert_eq!(header_bytes.len(), 320);
    let header: &PsyBridgeHeader = bytemuck::from_bytes(&header_bytes);

    let ix = instructions::block_update(
        program_id, payer.pubkey(), proof, *header,
        operator.pubkey(), mint_buffer, txo_buffer, mint_bump, txo_bump);

    println!("Accounts: {}", ix.accounts.len());
    println!("Data: {} bytes", ix.data.len());

    let cu_ix = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let blockhash = rpc.get_latest_blockhash().expect("blockhash");
    let tx = Transaction::new_signed_with_payer(
        &[cu_ix, ix], Some(&payer.pubkey()), &[&payer, &operator], blockhash);

    println!("Submitting...");
    match rpc.send_and_confirm_transaction(&tx) {
        Ok(sig) => println!("✅ block_update SUCCESS! Signature: {}", sig),
        Err(e) => eprintln!("❌ block_update FAILED: {}", e),
    }
}
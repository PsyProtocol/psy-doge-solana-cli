//! Initialize Wormhole Core Bridge on Solana devnet

use solana_client::rpc_client::RpcClient;
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signer::keypair::read_keypair_file;
use solana_sdk::signer::Signer;
use solana_sdk::sysvar;
use solana_sdk::system_program;
use solana_sdk::transaction::Transaction;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let rpc_url = args.get(1).cloned().unwrap_or_else(|| "https://api.devnet.solana.com".to_string());
    let payer_path = args.get(2).cloned().unwrap_or_else(|| "bridge-config/keys/payer.json".to_string());

    println!("=== Initialize Wormhole Core Bridge on devnet ===");
    let payer = read_keypair_file(&payer_path).expect("read payer");
    println!("Payer: {}", payer.pubkey());

    let rpc = RpcClient::new(&rpc_url);
    let core_bridge = Pubkey::from_str_const("3u8hJUVTA4jH1wYAyUur7FFZVQ8H635K3tSHHF4ssjQ5");

    // Derive PDAs (solitaire uses find_program_address)
    let (bridge_config, _) = Pubkey::find_program_address(&[b"Bridge"], &core_bridge);
    let (guardian_set, _) = Pubkey::find_program_address(&[b"guardian_set", &[0u8, 0, 0, 0]], &core_bridge);
    let (fee_collector, _) = Pubkey::find_program_address(&[b"fee_collector"], &core_bridge);

    println!("Core Bridge: {}", core_bridge);
    println!("Bridge config: {}", bridge_config);
    println!("Guardian set: {}", guardian_set);
    println!("Fee collector: {}", fee_collector);

    // Check if already initialized
    match rpc.get_account(&bridge_config) {
        Ok(_) => { println!("Bridge already initialized!"); return; }
        Err(_) => println!("Bridge not initialized, proceeding..."),
    }

    // Construct initialize instruction data manually (Borsh format)
    // Byte 0: Instruction::Initialize discriminator = 0x00
    // Then InitializeData (Borsh):
    //   guardian_set_expiration_time: u32 LE
    //   fee: u64 LE
    //   initial_guardians: Vec<[u8;20]> -> 4-byte LE length + N*20 bytes
    let guardian_set_expiration_time: u32 = 86400; // 24 hours
    let fee: u64 = 0; // 0 lamports fee for devnet testing
    let guardians: Vec<[u8; 20]> = vec![[0u8; 20]]; // 1 dummy guardian

    let mut ix_data = Vec::new();
    ix_data.push(0u8); // Initialize discriminator
    ix_data.extend_from_slice(&guardian_set_expiration_time.to_le_bytes());
    ix_data.extend_from_slice(&fee.to_le_bytes());
    ix_data.extend_from_slice(&(guardians.len() as u32).to_le_bytes()); // Vec length
    for g in &guardians {
        ix_data.extend_from_slice(g);
    }

    let init_ix = Instruction {
        program_id: core_bridge,
        accounts: vec![
            AccountMeta::new(bridge_config, false),
            AccountMeta::new(guardian_set, false),
            AccountMeta::new(fee_collector, false),
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(sysvar::clock::id(), false),
            AccountMeta::new_readonly(sysvar::rent::id(), false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: ix_data,
    };

    let blockhash = rpc.get_latest_blockhash().expect("blockhash");
    let tx = Transaction::new_signed_with_payer(
        &[init_ix], Some(&payer.pubkey()), &[&payer], blockhash);

    match rpc.send_and_confirm_transaction(&tx) {
        Ok(sig) => println!("✅ Wormhole initialized: {}", sig),
        Err(e) => eprintln!("❌ Initialize failed: {}", e),
    }

    // Verify
    match rpc.get_account(&bridge_config) {
        Ok(acct) => println!("Bridge config exists! Owner: {}, data len: {}", acct.owner, acct.data.len()),
        Err(e) => eprintln!("Bridge config still not found: {}", e),
    }
}
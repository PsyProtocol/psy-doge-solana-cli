use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signer::keypair::read_keypair_file;
use solana_sdk::signer::Signer;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let rpc = RpcClient::new(args.get(1).cloned().unwrap_or("https://api.devnet.solana.com".into()));
    let core = Pubkey::from_str_const("3u8hJUVTA4jH1wYAyUur7FFZVQ8H635K3tSHHF4ssjQ5");
    let shim = Pubkey::from_str_const("EtZMZM22ViKMo4r5y4Anovs3wKQ2owUmDpjygnMMcdEX");
    let emitter = Pubkey::from_str_const("9vzbk8X27e6VRcCPWCyxZsa2DV6GLQ3y9e1mXzfAgUdX");

    let (bc, _) = Pubkey::find_program_address(&[b"Bridge"], &core);
    let (gs, _) = Pubkey::find_program_address(&[b"guardian_set", &[0u8,0,0,0]], &core);
    let (fc, _) = Pubkey::find_program_address(&[b"fee_collector"], &core);
    let (seq, _) = Pubkey::find_program_address(&[b"Sequence", emitter.as_ref()], &core);
    let (msg, _) = Pubkey::find_program_address(&[emitter.as_ref()], &shim);
    let (ea, _) = Pubkey::find_program_address(&[b"__event_authority"], &shim);

    for (name, key) in [("bridge_config", bc), ("guardian_set", gs), ("fee_collector", fc), ("sequence", seq), ("message", msg), ("event_authority", ea)] {
        match rpc.get_account(&key) {
            Ok(acct) => println!("{} ({}) → EXISTS owner={} len={}", name, key, acct.owner, acct.data.len()),
            Err(_) => println!("{} ({}) → NOT FOUND", name, key),
        }
    }
}

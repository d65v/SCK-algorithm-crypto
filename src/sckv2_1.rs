//! sckv2_1 — SCK v2.1 CLI
//!
//! Usage:
//!   sckv2_1 encrypt <PLAINTEXT> <KEY>
//!   sckv2_1 decrypt <PACKET>    <KEY>
//!   sckv2_1 info    <KEY>             ← shows derived round count
//!
//! Input: printable ASCII 32–126. Quote arguments containing spaces or symbols.
//! Packet is a self-contained printable ASCII string — no side-channel needed.

use sck_crypto::{sck_encrypt, sck_decrypt, round_count};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 3 {
        eprintln!("SCK v2.1 — Signature CryptoKey");
        eprintln!();
        eprintln!("Usage:");
        eprintln!("  sckv2_1 encrypt \"<PLAINTEXT>\" <KEY>");
        eprintln!("  sckv2_1 decrypt \"<PACKET>\"    <KEY>");
        eprintln!("  sckv2_1 info    <KEY>");
        std::process::exit(1);
    }

    match args[1].as_str() {
        "encrypt" => {
            if args.len() != 4 { eprintln!("encrypt requires: <PLAINTEXT> <KEY>"); std::process::exit(1); }
            match sck_encrypt(&args[2], &args[3]) {
                Some(packet) => {
                    let n = round_count(&args[3]);
                    println!("Rounds : {}", n);
                    println!("Packet : {}", packet);
                }
                None => { eprintln!("Error: plaintext must be printable ASCII (0x20–0x7E)"); std::process::exit(1); }
            }
        }
        "decrypt" => {
            if args.len() != 4 { eprintln!("decrypt requires: <PACKET> <KEY>"); std::process::exit(1); }
            match sck_decrypt(&args[2], &args[3]) {
                Some(plain) => println!("Plain  : {}", plain),
                None        => { eprintln!("Error: decryption failed (wrong key or corrupt packet)"); std::process::exit(1); }
            }
        }
        "info" => {
            if args.len() != 3 { eprintln!("info requires: <KEY>"); std::process::exit(1); }
            println!("Key    : {}", args[2]);
            println!("Rounds : {}", round_count(&args[2]));
        }
        cmd => {
            eprintln!("Unknown command '{}'. Use encrypt / decrypt / info.", cmd);
            std::process::exit(1);
        }
    }
}

// Copyright (C) 2025 Intel Corporation
// SPDX-License-Identifier: BSD-3-Clause

// TODO: Setup a quote retrieval HTTP(S) endpoint in the TD (by creating a variant of the fde-quote-gen code). Then, the script can retrieve the quote from outside the TD, handle the quote, send the necessary data to Trustee KBS, and retrieve the key. This is very important for TD that do not offer any login capability!
// TODO: Allow the user to decide which Quote attributes should matter for key retrieval.

use anyhow::{anyhow, Result};
use clap::Parser;
use std::path::Path;

use utils::{
    key_broker::{KBS, TrusteeKbs},
    quote::Quote,
};
use zeroize::Zeroize;

#[derive(Parser)]
#[command(disable_help_flag = true)]
struct Args {
    #[arg(long)]
    auth_private_key_path: String,

    #[arg(long)]
    kbs_url: String,

    #[arg(long)]
    kbs_cert_path: String,

    #[arg(long)]
    kbs_resource_path: String,

    #[arg(long)]
    quote_b64: String,

    #[arg(long)]
    k_rfs: String,

    // Custom help to remove the default help message added by clap
    #[arg(short, long, action = clap::ArgAction::Help, help = "")]
    help: Option<bool>,
}

#[tokio::main(worker_threads = 1)]
async fn main() -> Result<()> {
    let args = Args::parse();
    let auth_private_key_path: String = args.auth_private_key_path;
    let kbs_url: String = args.kbs_url;
    let kbs_cert_path: String = args.kbs_cert_path;
    let kbs_resource_path: String = args.kbs_resource_path;
    let quote_b64: String = args.quote_b64;
    let k_rfs: String = args.k_rfs;

    // Check if public key file exists
    if !Path::new(&auth_private_key_path).exists() {
        println!("Auth key file \"{}\" that should be used for key retrieval does not exist. Please provide a valid auth private key file path.", auth_private_key_path);
        return Ok(());
    }

    if !Path::new(&kbs_cert_path).exists() {
        println!("KBS cert path \"{}\" does not exist. Please provide a valid KBS cert path.", kbs_cert_path);
        return Ok(())
    }

    // Initialize Trustee KBS.
    let kbs = TrusteeKbs::new(kbs_url, kbs_cert_path)
        .map_err(|e| anyhow!("Failed to create Trustee KBS: {}", e))?;

    // Convert incoming base64 encoded TD quote to a quote object and trigger key creation for this TD.
    let quote = Quote::from_b64(&quote_b64)?;

    // Store encryption key for rootfs in KBS
    let mut k_rfs_hex = kbs.store_k_rfs(&k_rfs, &auth_private_key_path, &quote, &kbs_resource_path).await.expect("Failed to create root file key");

    // Securely erase root file key from memory.
    k_rfs_hex.zeroize();

    Ok(())
 }

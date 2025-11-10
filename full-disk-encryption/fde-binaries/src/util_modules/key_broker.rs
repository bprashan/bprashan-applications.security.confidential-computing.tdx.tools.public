// Copyright (C) 2025 Intel Corporation
// SPDX-License-Identifier: BSD-3-Clause

use anyhow::{anyhow, Result};
use rsa::RsaPrivateKey;
use rsa::pkcs1::EncodeRsaPrivateKey;
use std::path::Path;
use std::fs;

use crate::quote::Quote;
use crate::disk::K_RFS_BIT_LENGTH;
use crate::kbs_protocol_api;

pub trait KBS {
    fn store_k_rfs(&self, k_rfs: &str, auth_private_key_path: &str, quote: &Quote, kbs_resource_path: &str) -> impl std::future::Future<Output = Result<String>> + Send;
    fn retrieve_k_rfs(&self, sk_kr: RsaPrivateKey, kbs_k_path: String) -> impl std::future::Future<Output = Result<Vec<u8>>> + Send;
}

pub struct TrusteeKbs {
    kbs_url: String,
    kbs_cert: Vec<String>,
}

/// Parameters for key transfer policy creation
///
/// These parameters are used to create a key transfer policy in the Trustee KBS.
/// The struct contains all measurement values from the quote that are required for attestation-based key release.
#[derive(Debug, Clone)]
struct KeyTransferPolicyParams {
    /// Measurement of Intel TDX Module
    mrseam: String,
    /// The measurement of the signing key used for the Intel TDX Module.
    mrsignerseam: String,
    /// SVN of Intel TDX Module (as combination of major and minor)
    seamsvn: String,
    /// Measurement of the initial contents of the TD
    mrtd: String,
    /// Runtime measurement register 1
    rtmr1: String,
    /// Runtime measurement register 0
    rtmr0: String,
    /// Runtime measurement register 3
    rtmr3: String,
}

impl TrusteeKbs {
    /// Creates a new instance of an Trustee KBS.
    ///
    /// # Parameters
    ///
    /// - `kbs_url`: The URL of the KBS.
    /// - `kbs_cert_path`: The file path to the KBS certificate.
    ///
    /// # Returns
    ///
    /// * `Result<Self>` - A result containing the new instance of an Trustee KBS.
    pub fn new(kbs_url: String, kbs_cert_path: String) -> Result<Self> {
        let cert_pem = fs::read_to_string(&kbs_cert_path)
            .map_err(|e| anyhow!(
                "Failed to read KBS certificate file '{}': {}",
                kbs_cert_path, e
            ))?;

        let kbs_certs_pem = vec![cert_pem];

        Ok(Self {
            kbs_url: kbs_url,
            kbs_cert: kbs_certs_pem,
        })
    }

    /// Create an attestation policy for Trustee KBS
    async fn create_trustee_attestation_policy(
        &self,
        auth_private_key_path: &str,
        params: KeyTransferPolicyParams,
    ) -> Result<()> {
        // Create policy in rego format
        let policy_content = format!(
            r#"package policy
                import rego.v1
                default allow = false

                allow if {{
                    input["tdx.quote.body.rtmr_1"] == "{}"
                    input["tdx.quote.body.rtmr_0"] == "{}"
                    input["tdx.quote.body.rtmr_3"] == "{}"
                    input["tdx.quote.body.mr_seam"] == "{}"
                    input["tdx.quote.body.mrsigner_seam"] == "{}"
                    input["tdx.quote.body.mr_td"] == "{}"
                    input["tdx.quote.body.tcb_svn"] == "{}"
                }}
                "#,
            params.rtmr1,
            params.rtmr0,
            params.rtmr3,
            params.mrseam,
            params.mrsignerseam,
            params.mrtd,
            params.seamsvn
        );

        // Check if auth private key file exists
        if !Path::new(auth_private_key_path).exists() {
            return Err(anyhow!(
                "Auth private key file not found: {}",
                auth_private_key_path
            ));
        }

        let auth_private_key = fs::read_to_string(auth_private_key_path)?;

        // fetch and save KBS certificate
        kbs_protocol_api::set_attestation_policy(
            &self.kbs_url,
            auth_private_key,
            policy_content.as_bytes().to_vec(),
            Some("rego".to_string()),
            Some("default".to_string()),
            self.kbs_cert.clone(),
        )
        .await?;

        println!("Attestation policy successfully set for Trustee KBS");
        Ok(())
    }

    /// Generates k_rfs key and sets it in Trustee KBS
    async fn set_k_rfs(&self, k_rfs: &str, auth_private_key_path: &str, kbs_resource_path: &str) -> Result<String> {

        // Check if auth private key file exists
        if !Path::new(auth_private_key_path).exists() {
            return Err(anyhow!(
                "Auth private key file not found: {}",
                auth_private_key_path
            ));
        }

        let auth_private_key = fs::read_to_string(auth_private_key_path)?;

        kbs_protocol_api::set_resource(
            &self.kbs_url,
            auth_private_key,
            k_rfs.as_bytes().to_vec(),
            kbs_resource_path,
            self.kbs_cert.clone(),
        )
        .await?;

        println!(
            "Successfully set k_rfs resource in Trustee KBS at path: {}",
            kbs_resource_path
        );

        // Return the key as hex format for Trustee KBS
        Ok(k_rfs.to_string())
    }
}

impl KBS for TrusteeKbs {
    async fn store_k_rfs(&self, k_rfs: &str, auth_private_key_path: &str, quote: &Quote, kbs_resource_path: &str) -> Result<String> {
        // Extract values from the Quote object
        let (mrseam, mrsignerseam, seamsvn, mrtd, rtmr1, rtmr0, rtmr3) = match quote {
            Quote::V4(q) => (
                hex::encode(q.report_body.mr_seam.m),
                hex::encode(q.report_body.mrsigner_seam.m),
                q.get_intel_tdx_module_version(),
                hex::encode(q.report_body.mr_td.m),
                hex::encode(q.report_body.rt_mr[1].m),
                hex::encode(q.report_body.rt_mr[0].m),
                hex::encode(q.report_body.rt_mr[3].m),
            ),
        };

        // Construct parameters to set attestation policy.
        let policy_params = KeyTransferPolicyParams {
            mrseam,
            mrsignerseam,
            seamsvn,
            mrtd,
            rtmr1,
            rtmr0,
            rtmr3,
        };
        
        // Create attestation policy for Trustee KBS
        self.create_trustee_attestation_policy(auth_private_key_path, policy_params)
            .await?;

        // Generate and set the k_rfs key
        let k_rfs_hex = self
            .set_k_rfs(k_rfs, auth_private_key_path, kbs_resource_path)
            .await?;

        Ok(k_rfs_hex)
    }

    async fn retrieve_k_rfs(&self, sk_kr: RsaPrivateKey, kbs_k_path: String) -> Result<Vec<u8>> {
        // Create tee_key_pem. Public key (PEM format) of the RSA key pair generated in TEE.
        // let tee_key_pem = sk_kr.to_pkcs1_pem(Default::default())?.to_string();
        let tee_key_pem = sk_kr
            .to_pkcs1_pem(Default::default())
            .map_err(|e| anyhow!("Failed to encode RSA key as PKCS#1 PEM: {}", e))?
            .to_string();

        // FDE key retrieval request.
        let resource_bytes = kbs_protocol_api::get_resource_with_attestation(
            &self.kbs_url,
            &kbs_k_path,
            Some(tee_key_pem),
            self.kbs_cert.clone(),
        )
        .await?;

        let hex_string = String::from_utf8(resource_bytes)
            .map_err(|e| anyhow!("Retrieved resource is not valid UTF-8: {}", e))?;

        let k_rfs = hex::decode(hex_string.trim()).map_err(|e| anyhow!("Retrieved key is not valid hex: {}", e))?;

        // Check for expected key length.
        if k_rfs.len() != (K_RFS_BIT_LENGTH / 8) {
           return Err(anyhow!(
                "Length of k_rfs is not as expected: got {}, expected {}",
                k_rfs.len(),
                K_RFS_BIT_LENGTH / 8
            ));
        }

        println!("Successfully retrieved k_rfs from Trustee KBS");    
        Ok(k_rfs)
    }
}

// Copyright 2025 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

use borsh::{BorshDeserialize, BorshSerialize};
use clap::Parser;
use risc0_zkvm::ProverOpts;
use risc0_zkvm::recursion::MerkleProof;
use risc0_zkvm::sha::Digestible;
use risc0_zkvm::{ExecutorEnv, Receipt, default_prover, sha::Digest};
use sha_methods::{HASH_ELF, HASH_ID, HASH_RUST_CRYPTO_ELF};
use std::fs::File;
use std::io::Write;

#[derive(Debug, BorshDeserialize, BorshSerialize)]
pub struct SuccinctReceipt {
    /// The cryptographic seal of this receipt. This seal is a STARK proving an execution of the
    /// recursion circuit.
    pub seal: Vec<u32>,

    /// The control ID of this receipt, identifying the recursion program that was run (e.g. lift,
    /// join, or resolve).
    pub control_id: Digest,

    /// Claim containing information about the computation that this receipt proves.
    ///
    /// The standard claim type is [ReceiptClaim][crate::ReceiptClaim], which represents a RISC-V
    /// zkVM execution.
    pub claim: Digest,

    /// Name of the hash function used to create this receipt.
    pub hashfn: String,

    /// A digest of the verifier parameters that can be used to verify this receipt.
    ///
    /// Acts as a fingerprint to identify differing proof system or circuit versions between a
    /// prover and a verifier. It is not intended to contain the full verifier parameters, which must
    /// be provided by a trusted source (e.g. packaged with the verifier code).
    pub verifier_parameters: Digest,

    /// Merkle inclusion proof for control_id against the control root for this receipt.
    pub control_inclusion_proof: MerkleProof,
}

/// Hash the given bytes, returning the digest and a [Receipt] that can
/// be used to verify that the hash was computed correctly (i.e. that
/// the Prover knows a preimage for the given SHA-256 hash)
///
/// Select which method to use with `use_rust_crypto`.
/// HASH_ELF uses the risc0_zkvm::sha interface for hashing.
/// HASH_RUST_CRYPTO_ELF uses RustCrypto's [sha2] crate, patched to use the RISC
/// Zero accelerator. See `src/methods/guest/Cargo.toml` for the patch
/// definition, which can be used to enable SHA-256 accelerator support
/// everywhere the [sha2] crate is used.
fn provably_hash(input: &str, use_rust_crypto: bool) -> (Digest, Receipt) {
    let env = ExecutorEnv::builder()
        .write(&input)
        .unwrap()
        .build()
        .unwrap();

    let elf = if use_rust_crypto {
        HASH_RUST_CRYPTO_ELF
    } else {
        HASH_ELF
    };

    // Obtain the default prover.
    let prover = default_prover();

    // Produce a receipt by proving the specified ELF binary.
    let receipt = prover
        .prove_with_opts(env, elf, &ProverOpts::groth16())
        .unwrap()
        .receipt;
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    receipt.verify(HASH_ID).unwrap();

    let digest = receipt.journal.decode().unwrap();
    (digest, receipt)
}

#[derive(Parser)]
struct Cli {
    #[arg(default_value = "")]
    message: String,
}

fn main() {
    // Parse command line
    let args = Cli::parse();

    // Prove hash the message.
    let (digest, receipt) = provably_hash(&args.message, false);

    let inner_receipt = receipt.inner.succinct().unwrap();

    // Convert the inner receipt to our custom SuccinctReceipt type
    let custom_receipt = SuccinctReceipt {
        seal: inner_receipt.seal.clone(),
        control_id: inner_receipt.control_id,
        claim: inner_receipt.claim.digest(),
        hashfn: inner_receipt.hashfn.clone(),
        verifier_parameters: inner_receipt.verifier_parameters,
        control_inclusion_proof: inner_receipt.control_inclusion_proof.clone(),
    };

    println!("Seal size in bytes: {}", custom_receipt.seal.len() * 4);

    println!(
        "Control inclusion proof: {:?}",
        custom_receipt.control_inclusion_proof
    );

    // Hex encode the serialized receipt
    let hex_encoded = hex::encode(
        borsh::to_vec(&custom_receipt).expect("Failed to serialize receipt with Borsh"),
    );

    // Write to proof.hex file
    let mut file = File::create("proof.hex").expect("Failed to create proof.hex file");
    file.write_all(hex_encoded.as_bytes())
        .expect("Failed to write to proof.hex file");

    println!("Hex-encoded proof written to proof.hex");

    // Here is where one would send 'hex_encoded' over the network...

    // Verify the receipt, ensuring the prover knows a valid SHA-256 preimage.
    receipt
        .verify(HASH_ID)
        .expect("receipt verification failed");

    println!("I provably know data whose SHA-256 hash is {digest}");
}

#[cfg(test)]
mod tests {
    use crate::SuccinctReceipt;
    use sha_methods::{HASH_ID, HASH_RUST_CRYPTO_ID};
    use std::fs;

    #[test]
    #[gpu_guard::gpu_guard(skip_if_dev_mode = true)]
    fn hash_abc() {
        let (digest, receipt) = super::provably_hash("abc", false);
        receipt.verify(HASH_ID).unwrap();
        assert_eq!(
            hex::encode(digest.as_bytes()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "We expect to match the reference SHA-256 hash of the standard test value 'abc'"
        );
    }

    #[test]
    #[gpu_guard::gpu_guard(skip_if_dev_mode = true)]
    fn hash_abc_rust_crypto() {
        let (digest, receipt) = super::provably_hash("abc", true);
        receipt.verify(HASH_RUST_CRYPTO_ID).unwrap();
        assert_eq!(
            hex::encode(digest.as_bytes()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "We expect to match the reference SHA-256 hash of the standard test value 'abc'"
        );
    }

    #[test]
    fn test_deserialize_proof_hex() {
        // Read the hex-encoded proof from file
        let hex_encoded = fs::read_to_string("proof.hex").expect("Failed to read proof.hex file");

        // Decode from hex
        let serialized_receipt = hex::decode(&hex_encoded).expect("Failed to decode hex string");

        // Deserialize the inner receipt using Borsh
        borsh::from_slice::<SuccinctReceipt>(&serialized_receipt)
            .expect("Failed to deserialize receipt with Borsh");

        println!("Successfully deserialized and verified receipt!");
        println!("Serialized size: {} bytes", serialized_receipt.len());
    }
}

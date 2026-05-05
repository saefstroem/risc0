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

use clap::Parser;
use risc0_zkvm::sha::Digestible;
use risc0_zkvm::ProverOpts;
use risc0_zkvm::{default_prover, sha::Digest, ExecutorEnv, Receipt};
use sha_methods::{HASH_ELF, HASH_ID, HASH_RUST_CRYPTO_ELF};
use std::fs::File;
use std::io::Write;

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

    receipt.verify(HASH_ID).unwrap();

    let digest = receipt.journal.decode().unwrap();
    (digest, receipt)
}

#[derive(Parser)]
struct Cli {
    #[arg(default_value = "")]
    message: String,
}
use risc0_zkvm::ReceiptClaim;

fn main() {
    // Parse command line
    let args = Cli::parse();

    // Prove hash the message.
    let (_digest, receipt) = provably_hash(&args.message, false);

    let inner_receipt: &risc0_zkvm::Groth16Receipt<ReceiptClaim> = receipt.inner.groth16().unwrap();

    // Hex encode the serialized receipt
    let hex_encoded =
        hex::encode(borsh::to_vec(&inner_receipt).expect("Failed to serialize receipt with Borsh"));

    //let groth_seal_hex = include_str!("data/groth16.seal.hex");
    //let groth_claim_hex = include_str!("data/groth16.claim.hex");
    //let groth_hashfn_hex = include_str!("data/groth16.hashfn.hex");
    //let groth_control_index_hex = include_str!("data/groth16.control_index.hex");
    //let groth_control_digests_hex = include_str!("data/groth16.control_digests.hex");
    //let groth_image_id_hex = include_str!("data/groth16.image.hex");
    //let stark_journal_hex = include_str!("data/succinct.journal.hex");
    println!(
        "seal hex: {:?}",
        hex::encode(
            inner_receipt
                .seal
                .iter()
                .flat_map(|x| x.to_le_bytes())
                .collect::<Vec<u8>>()
        )
    );
    println!(
        "claim hex: {:?}",
        hex::encode(inner_receipt.claim.digest().as_bytes())
    );
    println!("raw claim: {:?}", inner_receipt.claim);

    // Write to proof.hex file
    let mut file = File::create("groth.hex").expect("Failed to create proof.hex file");
    file.write_all(hex_encoded.as_bytes())
        .expect("Failed to write to proof.hex file");

    println!("Hex-encoded proof written to groth.hex");

    // Here is where one would send 'hex_encoded' over the network...
    println!("hashid:{:?}", HASH_ID);
    let digest = Digest::new(HASH_ID);

    println!("sha groth image id hex:{:?}", digest);
    // Verify the receipt, ensuring the prover knows a valid SHA-256 preimage.

    let digest = receipt.journal.digest();
    println!("journal digest:{:?}", digest);
    receipt
        .verify(HASH_ID)
        .expect("receipt verification failed");

    println!("I provably know data whose SHA-256 hash is {digest}");
}

#[cfg(test)]
mod tests {
    use hex::FromHex;
    use sha_methods::HASH_ID;

    // [1423791584, 880512669, 1738307172, 2533723364, 3880046003, 402541997, 1959133478, 277067013]
    use risc0_zkvm::{sha::Digestible, Digest, Groth16Receipt, MaybePruned, ReceiptClaim};
    #[test]
    fn hash_abcd() {
        let digest = Digest::new([
            1753878241, 1141607696, 453267234, 360392654, 2778692852, 1769103400, 220658553,
            3032668356,
        ]);

        println!("sha succinct image id hex:{:?}", digest);
    }

    #[test]
    fn hash_abc() {
        let (digest, receipt) = super::provably_hash("abc", false);
        receipt.verify(HASH_ID).unwrap();
        assert_eq!(
            hex::encode(digest.as_bytes()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "We expect to match the reference SHA-256 hash of the standard test value 'abc'"
        );
    }

    fn compute_receipt_claim_hash(journal_hash: &[u8; 32], image_id: &[u8; 32]) -> [u8; 32] {
        // Step 1: Compute Output digest first
        let output_digest = compute_output_digest(journal_hash);

        // Step 2: Compute ReceiptClaim digest
        compute_receipt_claim_digest(image_id, &output_digest)
    }

    fn compute_output_digest(journal_hash: &[u8; 32]) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        // Hash the "risc0.Output" tag
        let tag_digest = Sha256::digest(b"risc0.Output");

        // Build concatenated data: tag + journal + assumptions(ZERO) + count(2)
        let mut all = Vec::new();
        all.extend_from_slice(&tag_digest);
        all.extend_from_slice(journal_hash);
        all.extend_from_slice(&[0u8; 32]); // Digest::ZERO for assumptions
        all.extend_from_slice(&2u16.to_le_bytes()); // 2 components

        Sha256::digest(&all).into()
    }

    fn compute_receipt_claim_digest(image_id: &[u8; 32], output_digest: &[u8; 32]) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        // Fixed post digest from your logs
        let post_digest =
            hex::decode("a3acc27117418996340b84e5a90f3ef4c49d22c79e44aad822ec9c313e1eb8e2")
                .unwrap();

        // Hash the "risc0.ReceiptClaim" tag
        let tag_digest = Sha256::digest(b"risc0.ReceiptClaim");

        // Build concatenated data: tag + input(ZERO) + pre(image_id) + post + output + exit_codes + count(4)
        let mut all = Vec::new();
        all.extend_from_slice(&tag_digest);
        all.extend_from_slice(&[0u8; 32]); // input = Digest::ZERO
        all.extend_from_slice(image_id); // pre = image_id
        all.extend_from_slice(&post_digest); // post (fixed)
        all.extend_from_slice(output_digest); // output (computed)
        all.extend_from_slice(&0u32.to_le_bytes()); // sys_exit = 0
        all.extend_from_slice(&0u32.to_le_bytes()); // user_exit = 0
        all.extend_from_slice(&4u16.to_le_bytes()); // 4 components

        Sha256::digest(&all).into()
    }

    #[test]
    fn g16_hash_fix() {
        let groth_receipt_raw = include_str!("groth.rcpt.hex");
        let rcpt: Groth16Receipt<ReceiptClaim> =
            borsh::from_slice(&hex::decode(groth_receipt_raw).unwrap()).unwrap();
        rcpt.verify_integrity().unwrap();
        println!("inner rcpt claim: {:?}", rcpt.claim.digest());
        let seal_hex = hex::encode(rcpt.seal);
        println!("seal hex: {:?}", seal_hex);
        let rcpt_claim = ReceiptClaim::ok(
            Digest::from_hex("75641a540ee2ad9ee5902bcdcdb8b55c0bef4a28287309b858f97b1356c6c2e0")
                .unwrap(),
            MaybePruned::Pruned(
                Digest::from_hex(
                    "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456",
                )
                .unwrap(),
            ),
        );

        let rcpt_claim_manual = compute_receipt_claim_hash(
            &hex::decode("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456")
                .unwrap()
                .try_into()
                .unwrap(),
            &hex::decode("75641a540ee2ad9ee5902bcdcdb8b55c0bef4a28287309b858f97b1356c6c2e0")
                .unwrap()
                .try_into()
                .unwrap(),
        );
        println!(
            "manual rcpt claim hash: {:?}",
            hex::encode(rcpt_claim_manual)
        );
        println!("rcpt_claim: {:?}", rcpt_claim.digest());
        println!("rcp_claim from receipt: {:?}", rcpt.claim.digest());
    }
}

// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This file is automatically generated.

use risc0_zkp::core::digest::Digest;
use risc0_zkp::digest;

pub const KECCAK_CONTROL_IDS: &[Digest] = &[
    digest!("610d232218fa810090df341268059e6d34de95531ed47742770bf3278680cc6d"), // keccak_lift po2=14
    digest!("72ac292e7bac750a3543b84d0994ba34a471025fe68fd710595383555566271a"), // keccak_lift po2=15
    digest!("0d1c2772c28cca62aa8568112406502d1d7c3241cbc6d9442159c60f73451560"), // keccak_lift po2=16
    digest!("d67ee915cfecf608336cad09b34700682c55d634768444646b7d8c1ab2c33048"), // keccak_lift po2=17
];

pub const KECCAK_CONTROL_ROOT: Digest =
    digest!("78322a078cb5942768766c2501752163b5f2791573ad1a0b4c42f85cd3dc275a");

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

pub const ALLOWED_CONTROL_IDS: &[&str] = &[
    "30dae603fcd283331d01105ea129ce43a0957a59b4f0013359a5642dfda0ba26",
    "2afea6024b79430b49f60518f27d7262f2ec5b1306a9030cc2e4d955e5dc5964",
    "8dc2760e1e24082cb66c83470c24a8017e95ce4d5eab170522f783418d545e72",
    "35feaa4eebbefd45b0a36a350671c82154f90c660389ed3a8ff7bd2a30805973",
    "7436486fdf9a7d3a3f8a03263bc7541a3c173c2ab5d2eb2c53939d0243dc0d16",
    "3abdc115ddf6af1977863c29c0f2b91f8c0c2a1c35e82158104b651f6a07a816",
    "17d75c070f373f333bbbaf33a688bb74fc05670435cd5d6378d37b608448e300",
    "f3cf1217485c403cea526b1e52e70835c31bdc6e3016ee12916f6c6561fc0977",
    "4043ce1426811d4f0e6a9c27256d052513c95739e9b80c74f628f313c739b75c",
    "b4edfc3f2c49f10285bcdc7493eb81063959820a59569356fb73b62c1586e01f",
    "cc1bd6753bb8fd41d41bba14bb56e90ffa9ddf4f20f7727734d140675a9cc52b",
    "4882cd253cc9c775ca50d63162756140aa910608886b9c3f97d0d55653a86671",
    "bea76f74072983519b9ca337aae9e653b5468d721b1f9664c7bc2c50fa1fc236",
    "54f2492833c36345869f4b0c877c20283bb49e23d91f2221fc18483e1c3d8f62",
    "8ba9655c9c05b448bf45ed0252afae6ec7dbe51e48ac854b909e8a3634a77f46",
    "205aee38a87b8842baf45940820d4a35fa72f840155f404341209204afba365d",
    "b7d027515b61043b2c4332025f1c1a3b3d37801f306c064fa7a24468ff4ab52e",
    "94e63e70c527f37670e5a01e716b9c2424c9e741a3688c0d7c7d7d255e91a21d",
    "1b3f2e445ef19f462a5f570e0b61b43a84203c71af79913c447459048198a05d",
    "99e1c075b4777652d667fb5bd176323a8cdc3319b9bede4415ff2f6bb5acc501",
    "01f0065599a53470e5b94e4ff70e68178ec5c66255774f58e805d839d50f5a03",
    "173d6916af4a8826fb04d263bbfd75229c536b20969bc86e6e301e5de4d53313",
    "e788e63a7e9d9804f83aa34326caec3f1e871065400e9b7673479c2dd9ebed1c",
    "89270350893c3958d2463b1e5227b122a2868213d146c83fe99e9c584067fe52",
    "ea9f2c0e3d0fd2047a6f1b2c96f1dc15c3a9b6712b253f587a804511b9430248",
];

pub const ALLOWED_CONTROL_ROOT: &str =
    "ba8dcf1d7389cb21895e6652bd327f315bb8b86c62c8d1462e8b473eb6cb9626";

pub const BN254_CONTROL_ID: &str =
    "10ff834dbef62ccbba201ecd26a772e3036a075aacbaf47200679a11dcdcf10d";

pub const ZKR_CONTROL_IDS: [(&str, &str); 15] = [
    (
        "identity.zkr",
        "4882cd253cc9c775ca50d63162756140aa910608886b9c3f97d0d55653a86671",
    ),
    (
        "join.zkr",
        "bea76f74072983519b9ca337aae9e653b5468d721b1f9664c7bc2c50fa1fc236",
    ),
    (
        "lift_14.zkr",
        "54f2492833c36345869f4b0c877c20283bb49e23d91f2221fc18483e1c3d8f62",
    ),
    (
        "lift_15.zkr",
        "8ba9655c9c05b448bf45ed0252afae6ec7dbe51e48ac854b909e8a3634a77f46",
    ),
    (
        "lift_16.zkr",
        "205aee38a87b8842baf45940820d4a35fa72f840155f404341209204afba365d",
    ),
    (
        "lift_17.zkr",
        "b7d027515b61043b2c4332025f1c1a3b3d37801f306c064fa7a24468ff4ab52e",
    ),
    (
        "lift_18.zkr",
        "94e63e70c527f37670e5a01e716b9c2424c9e741a3688c0d7c7d7d255e91a21d",
    ),
    (
        "lift_19.zkr",
        "1b3f2e445ef19f462a5f570e0b61b43a84203c71af79913c447459048198a05d",
    ),
    (
        "lift_20.zkr",
        "99e1c075b4777652d667fb5bd176323a8cdc3319b9bede4415ff2f6bb5acc501",
    ),
    (
        "lift_21.zkr",
        "01f0065599a53470e5b94e4ff70e68178ec5c66255774f58e805d839d50f5a03",
    ),
    (
        "lift_22.zkr",
        "173d6916af4a8826fb04d263bbfd75229c536b20969bc86e6e301e5de4d53313",
    ),
    (
        "lift_23.zkr",
        "e788e63a7e9d9804f83aa34326caec3f1e871065400e9b7673479c2dd9ebed1c",
    ),
    (
        "lift_24.zkr",
        "89270350893c3958d2463b1e5227b122a2868213d146c83fe99e9c584067fe52",
    ),
    (
        "resolve.zkr",
        "ea9f2c0e3d0fd2047a6f1b2c96f1dc15c3a9b6712b253f587a804511b9430248",
    ),
    (
        "test_recursion_circuit.zkr",
        "ca7ade1f42976e5e103ad45c97e42963515f5b4b33076418e0a9390a576edd4e",
    ),
];

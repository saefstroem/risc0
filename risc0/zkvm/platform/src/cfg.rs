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
macro_rules! cfg_rust_runtime {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "rust-runtime")]
            #[cfg_attr(docsrs, doc(cfg(feature = "rust-runtime")))]
            $item
        )*
    }
}

macro_rules! cfg_panic_handler {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "panic-handler")]
            #[cfg_attr(docsrs, doc(cfg(feature = "panic-handler")))]
            $item
        )*
    }
}

macro_rules! cfg_entrypoint {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "entrypoint")]
            #[cfg_attr(docsrs, doc(cfg(feature = "entrypoint")))]
            $item
        )*
    }
}

macro_rules! cfg_getrandom {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "getrandom")]
            #[cfg_attr(docsrs, doc(cfg(feature = "getrandom")))]
            $item
        )*
    }
}

macro_rules! cfg_export_libm {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "export-libm")]
            #[cfg_attr(docsrs, doc(cfg(feature = "export-libm")))]
            $item
        )*
    }
}

macro_rules! cfg_export_syscalls {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "export-syscalls")]
            #[cfg_attr(docsrs, doc(cfg(feature = "export-syscalls")))]
            $item
        )*
    }
}
//## exports a `getrandom` implementation that panics
//#export-getrandom = ["dep:getrandom", "dep:bytemuck"]

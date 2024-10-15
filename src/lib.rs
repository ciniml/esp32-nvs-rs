//! # esp32-nvs crate
//!
//! `esp32-nvs` crate is library to generate ESP32 NVS partition data from Rust code.

//! # esp32-nvs クレート
//!
//! `esp32-nvs` create は ESP32 NVSパーティションのデータをRustから生成するためのライブラリです。

// main source file of esp32-nvs crate
// Copyright 2022-2024 Kenta Ida
// SPDX-License-Identifier: MIT
//

mod nvs_partition;

pub use nvs_partition::*;

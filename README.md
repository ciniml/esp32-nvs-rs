# Simple ESP32 NVS writer library for Rust

## Overview

A library for Rust to generate NVS partitions for ESP32.

## How to use

See `examples/write_simple.rs`.

1. Make `NvsPartition` by calling `NvsPartition::new`
3. call `NvsPartition::add_primitive_entry` to add primitive (u8, i8, u16, i16, u32, i32, u64, i64) values. 
Both namespace and key are must be represented by `NvsKey` type. (`NvsKey` is just a type alias of `heapless::String<15>`, because ESP32 NVS supports 15 + 1 (null terminator) string for namespace and key.)
4. call `NvsPartition::add_string_entry` to add string values.
5. call `NvsPartition::add_binary_entry` to add BLOBs.
6. call `NvsPartition::write` to write out the NVS partition content to a file.

```rust
use esp32_nvs::{NvsKey, NvsPartition};
use std::{fs::File, io::*, str::FromStr};

fn main() -> Result<()> {
    let mut file = File::create("output.bin")?;
    let mut partition: NvsPartition = NvsPartition::new();
    let namespace = NvsKey::from_str("hoge").unwrap();
    let mut long_data = [0u8; 4097];
    for i in 0..long_data.len() {
        long_data[i] = (i & 0xff) as u8;
    }
    let mut long_string = String::with_capacity((126 - 10 - 1) * 32 - 1);
    for i in 0..long_string.capacity() {
        long_string.push(char::from_u32(0x20 + (i % 0x40) as u32).unwrap());
    }
    partition.add_primitive_entry(
        &namespace,
        &NvsKey::from_str("fuga").unwrap(),
        0xdeadbeefu32,
    );
    partition
        .add_string_entry(
            &namespace,
            &NvsKey::from_str("long_value").unwrap(),
            "string",
        )
        .unwrap();
    partition
        .add_binary_entry(
            &namespace,
            &NvsKey::from_str("long_long_value").unwrap(),
            &long_data,
        )
        .unwrap();
    partition
        .add_string_entry(
            &namespace,
            &NvsKey::from_str("long_str").unwrap(),
            &long_string,
        )
        .unwrap();
    partition
        .add_string_entry(
            &namespace,
            &NvsKey::from_str("long_str2").unwrap(),
            &long_string,
        )
        .unwrap();
    partition.write(&mut file)?;

    Ok(())
}
```

## License

This library is available under the MIT License. See also [LICENSE](./LICENSE) file.
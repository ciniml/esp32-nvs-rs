use esp32_nvs::*;
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

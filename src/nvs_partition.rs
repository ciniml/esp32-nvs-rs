// nvs partition implementation
// Copyright 2022 Kenta Ida 
// SPDX-License-Identifier: MIT
//
use std::{collections::HashMap, vec::Vec};
use zerocopy::{AsBytes, ByteOrder, FromBytes, LittleEndian, Unaligned, U32};

// Use polynomial = 0x04c11db7, initial = 0x00000000, xorout = 0xffffffff (inverted) CRC32
const CRC_32_ZLIB: crc::Algorithm<u32> = crc::Algorithm {
    width: 32,
    poly: 0x04c11db7,
    init: 0x00000000,
    refin: true,
    refout: true,
    xorout: 0xffffffff,
    check: 0,
    residue: 0,
};
const NVS_CRC_ALGORITHM: &crc::Algorithm<u32> = &CRC_32_ZLIB;
const NVS_CRC: crc::Crc<u32> = crc::Crc::<u32>::new(NVS_CRC_ALGORITHM);

fn calculate_crc<'a, I>(chunks: I) -> u32
where
    I: 'a + IntoIterator<Item = &'a [u8]>,
{
    let mut digest = NVS_CRC.digest();
    for chunk in chunks {
        digest.update(chunk);
    }
    digest.finalize()
}

/// NVS Error type
#[derive(Debug)]
pub enum NvsError {
    /// The length of the specified string exceeds the limit of string length NVS partition supports.
    StringTooLarge,
}

// NVS Page state
#[derive(Clone, Copy, Debug)]
pub enum PageState {
    /// Uninitialized, all entries in the page is free.
    Uninitialized,
    /// Active, some entries are free and can add some entries.
    Active,
    /// Full, no entries are free and cannot add an entry.
    Full,
    /// Freeing, marked to erase.
    Freeing,
    /// Corrupted
    Corrupt,
    /// Invalid
    Invalid,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, AsBytes, Unaligned)]
pub struct RawPageState(U32<LittleEndian>);
impl RawPageState {
    const UNINITIALIZED: u32 = 0xffffffff;
    const ACTIVE: u32 = Self::UNINITIALIZED & !1;
    const FULL: u32 = Self::ACTIVE & !2;
    const FREEING: u32 = Self::FULL & !4;
    const CORRUPT: u32 = Self::FREEING & !8;
    const INVALID: u32 = 0;

    pub const fn new() -> Self {
        Self(U32::from_bytes([0xff; 4]))
    }
}

impl From<PageState> for RawPageState {
    fn from(from: PageState) -> Self {
        let value = match from {
            PageState::Uninitialized => Self::UNINITIALIZED,
            PageState::Active => Self::ACTIVE,
            PageState::Full => Self::FULL,
            PageState::Freeing => Self::FREEING,
            PageState::Corrupt => Self::CORRUPT,
            PageState::Invalid => Self::INVALID,
        };
        Self(U32::new(value))
    }
}
impl TryFrom<RawPageState> for PageState {
    type Error = ();
    fn try_from(value: RawPageState) -> Result<Self, Self::Error> {
        match value.0.get() {
            RawPageState::UNINITIALIZED => Ok(Self::Uninitialized),
            RawPageState::ACTIVE => Ok(Self::Active),
            RawPageState::FULL => Ok(Self::Full),
            RawPageState::FREEING => Ok(Self::Freeing),
            RawPageState::CORRUPT => Ok(Self::Corrupt),
            RawPageState::INVALID => Ok(Self::Invalid),
            _ => Err(()),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, AsBytes, Unaligned)]
pub struct PageHeader {
    state: RawPageState,
    sequence_no: U32<LittleEndian>,
    version: u8,
    unused: [u8; 19],
    crc32: U32<LittleEndian>,
}

impl PageHeader {
    #[allow(unused)]
    const VERSION1: u8 = 0xff;
    const VERSION2: u8 = 0xfe;
    pub const fn new() -> Self {
        Self {
            state: RawPageState::new(),
            sequence_no: U32::from_bytes([0xff; 4]),
            version: 0xff,
            unused: [0xff; 19],
            crc32: U32::from_bytes([0xff; 4]),
        }
    }
    pub fn update_crc(&mut self) {
        let new_crc = calculate_crc([&self.as_bytes()[4..28]]);
        self.crc32 = U32::new(new_crc);
    }
}
impl Default for PageHeader {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryState {
    Empty = 0b11,
    Written = 0b10,
    Erased = 0b00,
    Invalid = 0b01,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, AsBytes, Unaligned)]
pub struct EntryStateBitmap {
    bits: [u8; 32],
}
impl EntryStateBitmap {
    pub const fn new() -> Self {
        Self { bits: [0xff; 32] }
    }
    pub fn get(&self, index: usize) -> EntryState {
        assert!(index < 126);
        let total_bit_index = index * 2;
        let byte_index = total_bit_index >> 3;
        let bit_index = total_bit_index & 7;
        let value = (self.bits[byte_index] >> bit_index) & 3;
        match value {
            0b11 => EntryState::Empty,
            0b10 => EntryState::Written,
            0b01 => EntryState::Invalid,
            0b00 => EntryState::Erased,
            _ => unreachable!(),
        }
    }
    pub fn set(&mut self, index: usize, state: EntryState) -> &mut Self {
        assert!(index < 126);
        let total_bit_index = index * 2;
        let byte_index = total_bit_index >> 3;
        let bit_index = total_bit_index & 7;
        let value = match state {
            EntryState::Empty => 0b11,
            EntryState::Written => 0b10,
            EntryState::Erased => 0b00,
            _ => 0b00,
        };
        self.bits[byte_index] =
            (self.bits[byte_index] & !(0b11 << bit_index)) | (value << bit_index);
        self
    }
}

impl Default for EntryStateBitmap {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug)]
pub enum EntryType {
    U8 = 0x01,
    I8 = 0x11,
    U16 = 0x02,
    I16 = 0x12,
    U32 = 0x04,
    I32 = 0x14,
    U64 = 0x08,
    I64 = 0x18,
    Str = 0x21,
    BlobData = 0x42,
    BlobIdx = 0x48,
    Any = 0xff,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, AsBytes, Unaligned)]
pub struct RawEntryType(u8);
impl RawEntryType {
    pub const fn new() -> Self {
        Self(0xff)
    }
}
impl Default for RawEntryType {
    fn default() -> Self {
        Self::new()
    }
}

impl From<EntryType> for RawEntryType {
    fn from(value: EntryType) -> Self {
        match value {
            EntryType::U8 => Self(0x01),
            EntryType::I8 => Self(0x11),
            EntryType::U16 => Self(0x02),
            EntryType::I16 => Self(0x12),
            EntryType::U32 => Self(0x04),
            EntryType::I32 => Self(0x14),
            EntryType::U64 => Self(0x08),
            EntryType::I64 => Self(0x18),
            EntryType::Str => Self(0x21),
            EntryType::BlobData => Self(0x42),
            EntryType::BlobIdx => Self(0x48),
            EntryType::Any => Self(0xff),
        }
    }
}
impl TryFrom<RawEntryType> for EntryType {
    type Error = ();
    fn try_from(value: RawEntryType) -> Result<Self, Self::Error> {
        match value.0 {
            0x01 => Ok(EntryType::U8),
            0x11 => Ok(EntryType::I8),
            0x02 => Ok(EntryType::U16),
            0x12 => Ok(EntryType::I16),
            0x04 => Ok(EntryType::U32),
            0x14 => Ok(EntryType::I32),
            0x08 => Ok(EntryType::U64),
            0x18 => Ok(EntryType::I64),
            0x21 => Ok(EntryType::Str),
            0x42 => Ok(EntryType::BlobData),
            0x48 => Ok(EntryType::BlobIdx),
            0xff => Ok(EntryType::Any),
            _ => Err(()),
        }
    }
}

fn to_nvs_data<T: AsBytes>(from: T) -> [u8; 8] {
    let bytes = from.as_bytes();
    let mut result = [0xff; 8];
    result[0..bytes.len()].copy_from_slice(bytes);
    result
}
pub trait ToNvsData {
    const TYPE: EntryType;
    fn into_nvs_data(self) -> [u8; 8];
}

macro_rules! define_to_nvs_data {
    ($type:ty, $entry_type:ident) => {
        impl ToNvsData for $type {
            const TYPE: EntryType = EntryType::$entry_type;
            fn into_nvs_data(self) -> [u8; 8] {
                to_nvs_data(self)
            }
        }
    };
}
define_to_nvs_data!(u8, U8);
define_to_nvs_data!(i8, I8);
define_to_nvs_data!(u16, U16);
define_to_nvs_data!(i16, I16);
define_to_nvs_data!(u32, U32);
define_to_nvs_data!(i32, I32);
define_to_nvs_data!(u64, U64);
define_to_nvs_data!(i64, I64);

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, AsBytes, Unaligned)]
pub struct Entry {
    ns: u8,
    r#type: RawEntryType,
    span: u8,
    chunk_index: u8,
    crc32: U32<LittleEndian>,
    key: [u8; 16],
    data: [u8; 8],
}

impl Entry {
    pub const SIZE: usize = 32;
    pub const fn new() -> Self {
        Self {
            ns: 0xff,
            r#type: RawEntryType::new(),
            span: 0xff,
            chunk_index: 0xff,
            crc32: U32::from_bytes([0xff; 4]),
            key: [0xff; 16],
            data: [0xff; 8],
        }
    }
    pub fn update_crc(&mut self) {
        let bytes = self.as_bytes();
        let new_crc = calculate_crc([&bytes[0..4], &bytes[8..]]); // CRC without CRC32 field.
        self.crc32.set(new_crc);
    }
    pub fn new_namespace(namespace: &NvsKey, index: u8) -> Self {
        assert!(index > 0);
        let mut entry = Self {
            ns: 0, // Namespace entry
            r#type: EntryType::U8.into(),
            span: 1,
            chunk_index: 0xff,
            key: [0; 16],
            data: [0xff; 8],
            ..Default::default()
        };
        let namespace_bytes = namespace.as_bytes();
        entry.key[0..namespace_bytes.len()].copy_from_slice(namespace_bytes);
        entry.data[0] = index;
        entry.update_crc();
        entry
    }
    pub fn new_primitive<T: ToNvsData>(namespace_index: u8, key: &NvsKey, value: T) -> Self {
        assert!(namespace_index > 0);
        let mut entry = Self {
            ns: namespace_index, // Namespace entry
            r#type: T::TYPE.into(),
            span: 1,
            chunk_index: 0xff,
            key: [0; 16],
            data: value.into_nvs_data(),
            ..Default::default()
        };
        let key_bytes = key.as_bytes();
        entry.key[0..key_bytes.len()].copy_from_slice(key_bytes);
        entry.update_crc();
        entry
    }
    pub fn new_string_header(namespace_index: u8, key: &NvsKey, span: u8, data: &[u8]) -> Self {
        assert!(namespace_index > 0);
        let crc32 = calculate_crc([data, &[0x00]]);
        let mut entry_data = [0xff; 8];
        LittleEndian::write_u16(&mut entry_data[0..2], (data.len() + 1) as u16);
        LittleEndian::write_u32(&mut entry_data[4..8], crc32);

        let mut entry = Self {
            ns: namespace_index, // Namespace entry
            r#type: EntryType::Str.into(),
            span,
            chunk_index: 0xff,
            key: [0; 16],
            data: entry_data,
            ..Default::default()
        };
        let key_bytes = key.as_bytes();
        entry.key[0..key_bytes.len()].copy_from_slice(key_bytes);
        entry.update_crc();
        entry
    }
    pub fn new_blob_data(
        namespace_index: u8,
        key: &NvsKey,
        span: u8,
        chunk_index: u8,
        chunk_data: &[u8],
    ) -> Self {
        assert!(namespace_index > 0);
        let crc32 = {
            let crc = &NVS_CRC;
            let mut digest = crc.digest();
            digest.update(chunk_data);
            digest.finalize()
        };

        let mut entry_data = [0xff; 8];
        LittleEndian::write_u16(&mut entry_data[0..2], chunk_data.len() as u16);
        LittleEndian::write_u32(&mut entry_data[4..8], crc32);

        let mut entry = Self {
            ns: namespace_index, // Namespace entry
            r#type: EntryType::BlobData.into(),
            span,
            chunk_index,
            key: [0; 16],
            data: entry_data,
            ..Default::default()
        };
        let key_bytes = key.as_bytes();
        entry.key[0..key_bytes.len()].copy_from_slice(key_bytes);
        entry.update_crc();
        entry
    }
    pub fn new_blob_index(
        namespace_index: u8,
        key: &NvsKey,
        chunk_start: u8,
        chunk_count: u8,
        value_len: u32,
    ) -> Self {
        let mut entry_data = [0xff; 8];
        LittleEndian::write_u32(&mut entry_data[0..4], value_len);
        entry_data[4] = chunk_count;
        entry_data[5] = chunk_start;

        let mut entry = Self {
            ns: namespace_index, // Namespace entry
            r#type: EntryType::BlobIdx.into(),
            span: 1,
            chunk_index: 0xff,
            key: [0; 16],
            data: entry_data,
            ..Default::default()
        };
        let key_bytes = key.as_bytes();
        entry.key[0..key_bytes.len()].copy_from_slice(key_bytes);
        entry.update_crc();
        entry
    }
}
impl Default for Entry {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug)]
pub enum EntryOrData {
    Entry(Entry),
    Data([u8; 32]),
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct Page<const NUMBER_OF_ENTRIES: usize = { 4096 / 32 - 2 }>
{
    header: PageHeader,
    bitmap: EntryStateBitmap,
    entries: [EntryOrData; NUMBER_OF_ENTRIES],
}

impl<const NUMBER_OF_ENTRIES: usize> Page<NUMBER_OF_ENTRIES> {
    pub const NUMBER_OF_ENTRIES: usize = NUMBER_OF_ENTRIES;
    pub const fn size() -> usize {
        (NUMBER_OF_ENTRIES + 2) * 32
    }
    pub const fn new() -> Self {
        Self {
            header: PageHeader::new(),
            bitmap: EntryStateBitmap::new(),
            entries: [EntryOrData::Entry(Entry::new()); NUMBER_OF_ENTRIES],
        }
    }
    pub fn num_remaining_entries(&self) -> usize {
        (0..NUMBER_OF_ENTRIES)
            .filter(|index| self.bitmap.get(*index) == EntryState::Empty)
            .count()
    }
}

/// Fixed length (15 + 1) string to hold namespace and entry key string.
pub type NvsKey = heapless::String<15>;

pub struct NvsPartition<const NUMBER_OF_ENTRIES_IN_PAGE: usize = { 4096 / 32 - 2 }>
{
    namespaces: HashMap<NvsKey, u8>,
    pages: Vec<Page<NUMBER_OF_ENTRIES_IN_PAGE>>,
}

impl<const NUMBER_OF_ENTRIES: usize> Default for NvsPartition<NUMBER_OF_ENTRIES> {
    fn default() -> Self {
        Self::new()
    }
}
impl<const NUMBER_OF_ENTRIES: usize> NvsPartition<NUMBER_OF_ENTRIES> {
    const MINIMUM_NUMBER_OF_PAGES: usize = 3;

    pub fn new() -> Self {
        Self {
            namespaces: HashMap::new(),
            pages: Vec::new(),
        }
    }

    fn add_entry_or_data(&mut self, entry_or_data: EntryOrData) {
        let (page, index) = if let Some((page, index)) = self.pages.last_mut().and_then(|page| {
            (0..NUMBER_OF_ENTRIES)
                .find(|i| page.bitmap.get(*i) == EntryState::Empty)
                .map(|index| (page, index))
        }) {
            (page, index)
        } else {
            let page = self.new_page();
            (page, 0)
        };
        page.bitmap.set(index, EntryState::Written);
        page.entries[index] = entry_or_data;
    }
    fn new_page(&mut self) -> &mut Page<NUMBER_OF_ENTRIES> {
        let num_pages = self.pages.len();
        self.pages.push(Page::new());
        let page = self.pages.last_mut().unwrap();
        page.header.version = PageHeader::VERSION2;
        page.header.sequence_no = U32::new(num_pages as u32);
        page
    }
    fn num_remaining_entries(&self) -> usize {
        self.pages
            .last()
            .map_or(0, |page| page.num_remaining_entries())
    }

    fn get_or_add_namespace(&mut self, namespace: &NvsKey) -> u8 {
        if let Some(index) = self.namespaces.get(namespace) {
            *index
        } else {
            let new_index = (self.namespaces.len() + 1) as u8;
            let entry = Entry::new_namespace(namespace, new_index);
            self.add_entry_or_data(EntryOrData::Entry(entry));
            self.namespaces.extend([(namespace.clone(), new_index)]);
            new_index
        }
    }

    /// Add a primitive entry
    pub fn add_primitive_entry<T: ToNvsData>(
        &mut self,
        namespace: &NvsKey,
        key: &NvsKey,
        value: T,
    ) {
        let namespace_index = self.get_or_add_namespace(namespace);
        let entry = Entry::new_primitive(namespace_index, key, value);
        self.add_entry_or_data(EntryOrData::Entry(entry));
    }

    /// Add a string entry. 
    /// the length of string must be within `(NUMBER_OF_ENTRIES - 1) * Entry::SIZE` - 1, which is `(126 - 1) * 32 - 1 == 3999`
    pub fn add_string_entry(
        &mut self,
        namespace: &NvsKey,
        key: &NvsKey,
        value: &str,
    ) -> Result<(), NvsError> {
        let value_bytes = value.as_bytes();
        let value_len = value_bytes.len() + 1; // Include null terminator.
        let num_value_entries = (value_len + Entry::SIZE - 1) / Entry::SIZE;
        let num_required_entries = num_value_entries + 1;

        if num_required_entries > NUMBER_OF_ENTRIES {
            // String entry must within a page.
            return Err(NvsError::StringTooLarge);
        }

        if num_required_entries > self.num_remaining_entries() {
            // Add a new page
            self.new_page();
        }

        let namespace_index = self.get_or_add_namespace(namespace);
        let entry = Entry::new_string_header(
            namespace_index,
            key,
            num_required_entries as u8,
            value_bytes,
        );
        self.add_entry_or_data(EntryOrData::Entry(entry));

        let mut bytes_written = 0;
        while bytes_written < value_len {
            let bytes_remaining = value_len - bytes_written;
            let bytes_to_write = usize::min(Entry::SIZE, bytes_remaining);
            let mut bytes = [0xff; Entry::SIZE];
            if bytes_remaining <= Entry::SIZE {
                bytes[0..bytes_remaining - 1].copy_from_slice(&value_bytes[bytes_written..]);
                bytes[bytes_remaining - 1] = 0;
            } else {
                bytes.copy_from_slice(&value_bytes[bytes_written..bytes_written + Entry::SIZE]);
            }
            self.add_entry_or_data(EntryOrData::Data(bytes));
            bytes_written += bytes_to_write;
        }

        Ok(())
    }

    /// Add a BLOB entry.
    pub fn add_binary_entry(
        &mut self,
        namespace: &NvsKey,
        key: &NvsKey,
        value: &[u8],
    ) -> Result<(), NvsError> {
        let value_len = value.len();
        let namespace_index = self.get_or_add_namespace(namespace);

        let mut bytes_written = 0;
        let mut num_chunks = 0;
        while bytes_written < value_len {
            let num_remaining_entries = self.num_remaining_entries();
            let num_remaining_entries = if num_remaining_entries <= 1 {
                // Add a new page
                self.new_page();
                NUMBER_OF_ENTRIES
            } else {
                num_remaining_entries
            };

            // Write chunk
            let bytes_remaining = value_len - bytes_written;
            let chunk_size = usize::min((num_remaining_entries - 1) * Entry::SIZE, bytes_remaining);
            let mut chunk_data = &value[bytes_written..bytes_written + chunk_size];
            let span = (chunk_size + Entry::SIZE - 1) / Entry::SIZE + 1;
            assert!(span >= 1);
            assert!(span < NUMBER_OF_ENTRIES);
            let entry =
                Entry::new_blob_data(namespace_index, key, span as u8, num_chunks, chunk_data);
            self.add_entry_or_data(EntryOrData::Entry(entry));
            while !chunk_data.is_empty() {
                let mut bytes = [0xff; Entry::SIZE];
                let chunk_bytes_remaining = chunk_data.len();
                let chunk_bytes_to_write = usize::min(Entry::SIZE, chunk_bytes_remaining);
                bytes[..chunk_bytes_to_write].copy_from_slice(&chunk_data[..chunk_bytes_to_write]);
                self.add_entry_or_data(EntryOrData::Data(bytes));
                chunk_data = &chunk_data[chunk_bytes_to_write..];
            }

            bytes_written += chunk_size;
            num_chunks += 1;
        }

        // Write blob index
        let index_entry =
            Entry::new_blob_index(namespace_index, key, 0, num_chunks, value_len as u32);
        self.add_entry_or_data(EntryOrData::Entry(index_entry));

        Ok(())
    }

    fn finalize(&mut self) {
        for page in &mut self.pages {
            page.header.state = PageState::Full.into();
            page.header.update_crc()
        }
    }

    fn write_page<W: std::io::Write>(
        writer: &mut W,
        page: &Page<NUMBER_OF_ENTRIES>,
    ) -> std::io::Result<()> {
        writer.write_all(page.header.as_bytes())?;
        writer.write_all(page.bitmap.as_bytes())?;
        for entry in &page.entries {
            match entry {
                EntryOrData::Entry(ref entry) => writer.write_all(entry.as_bytes())?,
                EntryOrData::Data(ref data) => writer.write_all(data)?,
            }
        }
        Ok(())
    }

    fn write_encrypted_block<W: std::io::Write>(
        writer: &mut W,
        offset: usize,
        key: &[u8; 64],
        data: &[u8],
    ) -> std::io::Result<()> {
        const ADDRESS_SIZE: usize = core::mem::size_of::<usize>();
        let mut tweak = [0u8; 16];
        tweak[..ADDRESS_SIZE].copy_from_slice(&offset.to_le_bytes());
        let mut crypter = openssl::symm::Crypter::new(openssl::symm::Cipher::aes_256_xts(), openssl::symm::Mode::Encrypt, key, Some(&tweak))
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
        let mut buffer = [0u8; 32];
        crypter.update(data, &mut buffer).map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
        writer.write_all(&buffer)?;
        Ok(())
    }

    fn write_page_encrypted<W: std::io::Write>(
        writer: &mut W,
        page: &Page<NUMBER_OF_ENTRIES>,
        mut offset: usize,
        key: &[u8; 64],
    ) -> std::io::Result<()> {
        // page header and bitmap are not encrypted.
        writer.write_all(page.header.as_bytes())?;
        writer.write_all(page.bitmap.as_bytes())?;
        offset += 64;
        for entry in &page.entries {
            match entry {
                EntryOrData::Entry(ref entry) => Self::write_encrypted_block(writer, offset, key, &entry.as_bytes())?,
                EntryOrData::Data(ref data) => Self::write_encrypted_block(writer, offset, key,data)?,
            }
            offset += 32;
        }
        Ok(())
    }

    /// Write NVS partition to the `std::io::Write` stream.
    pub fn write<W: std::io::Write>(&mut self, mut writer: W) -> std::io::Result<()> {
        self.finalize();
        for page in &self.pages {
            Self::write_page(&mut writer, page)?;
        }
        if self.pages.len() < Self::MINIMUM_NUMBER_OF_PAGES {
            let pages_to_append = Self::MINIMUM_NUMBER_OF_PAGES - self.pages.len();
            let empty_page = Page::<NUMBER_OF_ENTRIES>::new();
            for _ in 0..pages_to_append {
                Self::write_page(&mut writer, &empty_page)?;
            }
        }
        Ok(())
    }

    /// Write encrypted NVS partition to the `std::io::Write` stream.
    pub fn write_encrypted<W: std::io::Write>(&mut self, mut writer: W, key: &NvsEncryptionKey) -> std::io::Result<()> {
        self.finalize();
        let bytes_per_page = (NUMBER_OF_ENTRIES + 2) * 32;
        let mut offset = 0;
        for page in &self.pages {
            Self::write_page_encrypted(&mut writer, page, offset, &key.key)?;
            offset += bytes_per_page;
        }
        if self.pages.len() < Self::MINIMUM_NUMBER_OF_PAGES {
            let pages_to_append = Self::MINIMUM_NUMBER_OF_PAGES - self.pages.len();
            let empty_page = Page::<NUMBER_OF_ENTRIES>::new();
            for _ in 0..pages_to_append {
                Self::write_page_encrypted(&mut writer, &empty_page, offset, &key.key)?;
                offset += bytes_per_page;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct NvsEncryptionKey {
    key: [u8; 64],
}

impl NvsEncryptionKey {
    // Create a new NVS encryption key.
    pub fn new(key: [u8; 64]) -> Self {
        Self { key }
    }

    // Generate a new NVS encryption key.
    pub fn generate() -> Self {
        let mut key = [0; 64];
        openssl::rand::rand_bytes(&mut key).unwrap();
        Self { key }
    }

    // Import NVS encryption key from a reader.
    pub fn import<R: std::io::Read>(&mut self, reader: &mut R) -> std::io::Result<()> {
        reader.read_exact(&mut self.key)?;
        let crc_expected = calculate_crc([&self.key[..]]);
        let mut crc_actual = [0; 4];
        reader.read_exact(&mut crc_actual)?;
        let crc_actual = u32::from_le_bytes(crc_actual);
        if crc_expected != crc_actual {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "CRC mismatch",
            ));
        }
        Ok(())
    }

    // Export NVS encryption key to a writer.
    pub fn export<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let crc = calculate_crc([&self.key[..]]);
        writer.write_all(&self.key)?;
        writer.write_all(&crc.to_le_bytes())?;
        let remaining = 4096 - (64 + 4);
        let mut padding = Vec::with_capacity(remaining);
        padding.resize(remaining, 0xff);
        writer.write_all(&padding)?;
        Ok(())
    }
}


#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_entry_state_bitmap() {
        let mut bitmap = EntryStateBitmap::new();
        {
            let bytes = bitmap.as_bytes();
            assert_eq!(bytes.len(), Entry::SIZE);
            assert_eq!(bytes, [0xff; Entry::SIZE]);
        }
        {
            bitmap.set(0, EntryState::Empty);
            let bytes = bitmap.as_bytes();
            assert_eq!(bytes, [0xff; 32]);
            assert_eq!(bitmap.get(0), EntryState::Empty);
        }
        {
            bitmap.set(0, EntryState::Written);
            let bytes = bitmap.as_bytes();
            assert_eq!(bytes[0], 0xfe);
            assert_eq!(bytes[1..], [0xff; 31]);
            assert_eq!(bitmap.get(0), EntryState::Written);
        }
        {
            bitmap.set(0, EntryState::Erased);
            let bytes = bitmap.as_bytes();
            assert_eq!(bytes[0], 0xfc);
            assert_eq!(bitmap.get(0), EntryState::Erased);
        }
        {
            bitmap.set(1, EntryState::Empty);
            let bytes = bitmap.as_bytes();
            assert_eq!(bytes[0], 0xfc);
            assert_eq!(bytes[1..], [0xff; 31]);
            assert_eq!(bitmap.get(1), EntryState::Empty);
        }
        {
            bitmap.set(1, EntryState::Written);
            let bytes = bitmap.as_bytes();
            assert_eq!(bytes[0], 0xf8);
            assert_eq!(bytes[1..], [0xff; 31]);
            assert_eq!(bitmap.get(1), EntryState::Written);
        }
        {
            bitmap.set(1, EntryState::Erased);
            let bytes = bitmap.as_bytes();
            assert_eq!(bytes[0], 0xf0);
            assert_eq!(bitmap.get(1), EntryState::Erased);
        }
        {
            bitmap.set(3, EntryState::Erased);
            let bytes = bitmap.as_bytes();
            assert_eq!(bytes[0], 0x30);
            assert_eq!(bitmap.get(3), EntryState::Erased);
        }
        {
            bitmap.set(4, EntryState::Erased);
            let bytes = bitmap.as_bytes();
            assert_eq!(bytes[0], 0x30);
            assert_eq!(bytes[1], 0xfc);
            assert_eq!(bitmap.get(4), EntryState::Erased);
        }
    }

    #[test]
    fn test_namespace_entry() {
        let entry = Entry::new_namespace(&NvsKey::from_str("hoge").unwrap(), 1);
        let bytes = entry.as_bytes();

        assert_eq!(bytes.len(), Entry::SIZE);
        assert_eq!(bytes[0], 0x00); // NS
        assert_eq!(bytes[1], 0x01); // Type = U8
        assert_eq!(bytes[2], 0x01); // Span = 1
        assert_eq!(bytes[3], 0xff); // ChunkIndex
        assert_eq!(&bytes[8..12], "hoge".as_bytes()); // Key
        assert_eq!(bytes[12], 0); // Key (terminator)
        assert_eq!(&bytes[13..24], [0x00; 11]); // Key (remaining)
        assert_eq!(
            &bytes[24..32],
            [0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        ); // Data
        let crc32 = calculate_crc([&bytes[0..4], &bytes[8..]]);
        assert_eq!(&bytes[4..8], crc32.as_bytes());
    }
    #[test]
    fn test_primitive_entry_u8() {
        let entry = Entry::new_primitive(0xaa, &NvsKey::from_str("hoge").unwrap(), 0xa5u8);
        let bytes = entry.as_bytes();

        assert_eq!(bytes.len(), Entry::SIZE);
        assert_eq!(bytes[0], 0xaa); // NS
        assert_eq!(bytes[1], 0x01); // Type = U8
        assert_eq!(bytes[2], 0x01); // Span = 1
        assert_eq!(bytes[3], 0xff); // ChunkIndex
        assert_eq!(&bytes[8..12], "hoge".as_bytes()); // Key
        assert_eq!(bytes[12], 0); // Key (terminator)
        assert_eq!(&bytes[13..24], [0x00; 11]); // Key (remaining)
        assert_eq!(
            &bytes[24..32],
            [0xa5, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        ); // Data
        let crc32 = calculate_crc([&bytes[0..4], &bytes[8..]]);
        assert_eq!(&bytes[4..8], crc32.as_bytes());
    }
    #[test]
    fn test_primitive_entry_i8() {
        let entry = Entry::new_primitive(0xaa, &NvsKey::from_str("hoge").unwrap(), -2i8);
        let bytes = entry.as_bytes();

        assert_eq!(bytes.len(), Entry::SIZE);
        assert_eq!(bytes[0], 0xaa); // NS
        assert_eq!(bytes[1], 0x11); // Type = I8
        assert_eq!(bytes[2], 0x01); // Span = 1
        assert_eq!(bytes[3], 0xff); // ChunkIndex
        assert_eq!(&bytes[8..12], "hoge".as_bytes()); // Key
        assert_eq!(bytes[12], 0); // Key (terminator)
        assert_eq!(&bytes[13..24], [0x00; 11]); // Key (remaining)
        assert_eq!(
            &bytes[24..32],
            [0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        ); // Data
        let crc32 = calculate_crc([&bytes[0..4], &bytes[8..]]);
        assert_eq!(&bytes[4..8], crc32.as_bytes());
    }
    #[test]
    fn test_primitive_entry_u16() {
        let entry = Entry::new_primitive(0xaa, &NvsKey::from_str("hoge").unwrap(), 0xdeadu16);
        let bytes = entry.as_bytes();

        assert_eq!(bytes.len(), Entry::SIZE);
        assert_eq!(bytes[0], 0xaa); // NS
        assert_eq!(bytes[1], 0x02); // Type = U16
        assert_eq!(bytes[2], 0x01); // Span = 1
        assert_eq!(bytes[3], 0xff); // ChunkIndex
        assert_eq!(&bytes[8..12], "hoge".as_bytes()); // Key
        assert_eq!(bytes[12], 0); // Key (terminator)
        assert_eq!(&bytes[13..24], [0x00; 11]); // Key (remaining)
        assert_eq!(
            &bytes[24..32],
            [0xad, 0xde, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        ); // Data
        let crc32 = calculate_crc([&bytes[0..4], &bytes[8..]]);
        assert_eq!(&bytes[4..8], crc32.as_bytes());
    }
    #[test]
    fn test_primitive_entry_i16() {
        let entry = Entry::new_primitive(0xaa, &NvsKey::from_str("hoge").unwrap(), -32768i16);
        let bytes = entry.as_bytes();

        assert_eq!(bytes.len(), Entry::SIZE);
        assert_eq!(bytes[0], 0xaa); // NS
        assert_eq!(bytes[1], 0x12); // Type = I16
        assert_eq!(bytes[2], 0x01); // Span = 1
        assert_eq!(bytes[3], 0xff); // ChunkIndex
        assert_eq!(&bytes[8..12], "hoge".as_bytes()); // Key
        assert_eq!(bytes[12], 0); // Key (terminator)
        assert_eq!(&bytes[13..24], [0x00; 11]); // Key (remaining)
        assert_eq!(
            &bytes[24..32],
            [0x00, 0x80, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        ); // Data
        let crc32 = calculate_crc([&bytes[0..4], &bytes[8..]]);
        assert_eq!(&bytes[4..8], crc32.as_bytes());
    }
    #[test]
    fn test_primitive_entry_u32() {
        let entry = Entry::new_primitive(0xaa, &NvsKey::from_str("hoge").unwrap(), 0xdeadbeefu32);
        let bytes = entry.as_bytes();

        assert_eq!(bytes.len(), Entry::SIZE);
        assert_eq!(bytes[0], 0xaa); // NS
        assert_eq!(bytes[1], 0x04); // Type = U32
        assert_eq!(bytes[2], 0x01); // Span = 1
        assert_eq!(bytes[3], 0xff); // ChunkIndex
        assert_eq!(&bytes[8..12], "hoge".as_bytes()); // Key
        assert_eq!(bytes[12], 0); // Key (terminator)
        assert_eq!(&bytes[13..24], [0x00; 11]); // Key (remaining)
        assert_eq!(
            &bytes[24..32],
            [0xef, 0xbe, 0xad, 0xde, 0xff, 0xff, 0xff, 0xff]
        ); // Data
        let crc32 = calculate_crc([&bytes[0..4], &bytes[8..]]);
        assert_eq!(&bytes[4..8], crc32.as_bytes());
    }
    #[test]
    fn test_primitive_entry_i32() {
        let entry = Entry::new_primitive(0xaa, &NvsKey::from_str("hoge").unwrap(), -0x80000000i32);
        let bytes = entry.as_bytes();

        assert_eq!(bytes.len(), Entry::SIZE);
        assert_eq!(bytes[0], 0xaa); // NS
        assert_eq!(bytes[1], 0x14); // Type = I32
        assert_eq!(bytes[2], 0x01); // Span = 1
        assert_eq!(bytes[3], 0xff); // ChunkIndex
        assert_eq!(&bytes[8..12], "hoge".as_bytes()); // Key
        assert_eq!(bytes[12], 0); // Key (terminator)
        assert_eq!(&bytes[13..24], [0x00; 11]); // Key (remaining)
        assert_eq!(
            &bytes[24..32],
            [0x00, 0x00, 0x00, 0x80, 0xff, 0xff, 0xff, 0xff]
        ); // Data
        let crc32 = calculate_crc([&bytes[0..4], &bytes[8..]]);
        assert_eq!(&bytes[4..8], crc32.as_bytes());
    }
    #[test]
    fn test_primitive_entry_u64() {
        let entry = Entry::new_primitive(
            0xaa,
            &NvsKey::from_str("hoge").unwrap(),
            0xdeadbeefcafeaa55u64,
        );
        let bytes = entry.as_bytes();

        assert_eq!(bytes.len(), Entry::SIZE);
        assert_eq!(bytes[0], 0xaa); // NS
        assert_eq!(bytes[1], 0x08); // Type = U64
        assert_eq!(bytes[2], 0x01); // Span = 1
        assert_eq!(bytes[3], 0xff); // ChunkIndex
        assert_eq!(&bytes[8..12], "hoge".as_bytes()); // Key
        assert_eq!(bytes[12], 0); // Key (terminator)
        assert_eq!(&bytes[13..24], [0x00; 11]); // Key (remaining)
        assert_eq!(
            &bytes[24..32],
            [0x55, 0xaa, 0xfe, 0xca, 0xef, 0xbe, 0xad, 0xde]
        ); // Data
        let crc32 = calculate_crc([&bytes[0..4], &bytes[8..]]);
        assert_eq!(&bytes[4..8], crc32.as_bytes());
    }
    #[test]
    fn test_primitive_entry_i64() {
        let entry = Entry::new_primitive(
            0xaa,
            &NvsKey::from_str("hoge").unwrap(),
            -0x8000000000000000i64,
        );
        let bytes = entry.as_bytes();

        assert_eq!(bytes.len(), Entry::SIZE);
        assert_eq!(bytes[0], 0xaa); // NS
        assert_eq!(bytes[1], 0x18); // Type = I64
        assert_eq!(bytes[2], 0x01); // Span = 1
        assert_eq!(bytes[3], 0xff); // ChunkIndex
        assert_eq!(&bytes[8..12], "hoge".as_bytes()); // Key
        assert_eq!(bytes[12], 0); // Key (terminator)
        assert_eq!(&bytes[13..24], [0x00; 11]); // Key (remaining)
        assert_eq!(
            &bytes[24..32],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80]
        ); // Data
        let crc32 = calculate_crc([&bytes[0..4], &bytes[8..]]);
        assert_eq!(&bytes[4..8], crc32.as_bytes());
    }
    #[test]
    fn test_entry_str() {
        let data = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
        let entry = Entry::new_string_header(
            0xbb,
            &NvsKey::from_str("0123456789abcde").unwrap(),
            0x7f,
            &data,
        );
        let bytes = entry.as_bytes();

        assert_eq!(bytes.len(), Entry::SIZE);
        assert_eq!(bytes[0], 0xbb); // NS
        assert_eq!(bytes[1], 0x21); // Type = Str
        assert_eq!(bytes[2], 0x7f); // Span = 0x7f
        assert_eq!(bytes[3], 0xff); // ChunkIndex
        assert_eq!(&bytes[8..23], "0123456789abcde".as_bytes()); // Key
        assert_eq!(bytes[23], 0); // Key (terminator)
        let data_crc = calculate_crc([&data[..], &[0x00]]);
        assert_eq!(&bytes[24..28], [0x07, 0x00, 0xff, 0xff]); // Data[0..4]
        assert_eq!(&bytes[28..32], data_crc.as_bytes()); // Data[4..8]
        let crc32 = calculate_crc([&bytes[0..4], &bytes[8..]]);
        assert_eq!(&bytes[4..8], crc32.as_bytes());
    }

    #[test]
    fn test_entry_blob_data() {
        let data = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
        let entry = Entry::new_blob_data(
            0xbb,
            &NvsKey::from_str("0123456789abcde").unwrap(),
            0x7f,
            2,
            &data,
        );
        let bytes = entry.as_bytes();

        assert_eq!(bytes.len(), Entry::SIZE);
        assert_eq!(bytes[0], 0xbb); // NS
        assert_eq!(bytes[1], 0x42); // Type = BlobData
        assert_eq!(bytes[2], 0x7f); // Span = 0x7f
        assert_eq!(bytes[3], 0x02); // ChunkIndex
        assert_eq!(&bytes[8..23], "0123456789abcde".as_bytes()); // Key
        assert_eq!(bytes[23], 0); // Key (terminator)
        let data_crc = calculate_crc([&data[..]]);
        assert_eq!(&bytes[24..28], [0x06, 0x00, 0xff, 0xff]); // Data[0..4]
        assert_eq!(&bytes[28..32], data_crc.as_bytes()); // Data[4..8]
        let crc32 = calculate_crc([&bytes[0..4], &bytes[8..]]);
        assert_eq!(&bytes[4..8], crc32.as_bytes());
    }
    #[test]
    fn test_entry_blob_index() {
        let entry = Entry::new_blob_index(
            0xbb,
            &NvsKey::from_str("0123456789abcde").unwrap(),
            0x7f,
            2,
            0xdeadbeef,
        );
        let bytes = entry.as_bytes();

        assert_eq!(bytes.len(), Entry::SIZE);
        assert_eq!(bytes[0], 0xbb); // NS
        assert_eq!(bytes[1], 0x48); // Type = BlobIndex
        assert_eq!(bytes[2], 0x01); // Span = 0x7f
        assert_eq!(bytes[3], 0xff); // ChunkIndex
        assert_eq!(&bytes[8..23], "0123456789abcde".as_bytes()); // Key
        assert_eq!(bytes[23], 0); // Key (terminator)
        assert_eq!(
            &bytes[24..32],
            [0xef, 0xbe, 0xad, 0xde, 0x02, 0x7f, 0xff, 0xff]
        ); // Data
        let crc32 = calculate_crc([&bytes[0..4], &bytes[8..]]);
        assert_eq!(&bytes[4..8], crc32.as_bytes());
    }

    #[test]
    fn test_page_header() {
        let mut header = PageHeader::new();
        assert_eq!(header.as_bytes(), [0xff; Entry::SIZE]);
        header.state = PageState::Active.into();
        assert_eq!(&header.as_bytes()[0..4], 0xfffffffeu32.as_bytes());
        header.state = PageState::Full.into();
        assert_eq!(&header.as_bytes()[0..4], 0xfffffffcu32.as_bytes());
        header.state = PageState::Freeing.into();
        assert_eq!(&header.as_bytes()[0..4], 0xfffffff8u32.as_bytes());
        header.state = PageState::Corrupt.into();
        assert_eq!(&header.as_bytes()[0..4], 0xfffffff0u32.as_bytes());
        header.state = PageState::Invalid.into();
        assert_eq!(&header.as_bytes()[0..4], 0x00000000u32.as_bytes());
        header.sequence_no = U32::new(0xdeadbeef);
        assert_eq!(&header.as_bytes()[4..8], 0xdeadbeefu32.as_bytes());
        header.version = PageHeader::VERSION2;
        assert_eq!(header.as_bytes()[8], PageHeader::VERSION2);
        assert_eq!(&header.as_bytes()[9..28], [0xff; 19]);

        header.update_crc();
        let crc32 = calculate_crc([&header.as_bytes()[4..28]]);
        assert_eq!(header.crc32.get(), crc32);
    }

    #[test]
    fn test_crc_algorithm() {
        let header = [
            0xfcu8, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x84, 0x2d, 0xba, 0xb9,
        ];
        let header_crc32 = calculate_crc([&header[4..28]]);
        println!(
            "crc: {:08X}, expected: {:08X}",
            header_crc32,
            LittleEndian::read_u32(&header[28..])
        );
        assert_eq!(header_crc32.as_bytes(), &header[28..]);
    }

    #[test]
    fn test_encryption_key() {
        let key_1 = [0x11u8; 32];
        let key_2 = [0x22u8; 32];
        let mut key = [0; 64];
        key[..32].copy_from_slice(&key_1);
        key[32..].copy_from_slice(&key_2);

        let key = NvsEncryptionKey::new(key);
        let mut buffer = Vec::new();
        key.export(&mut buffer).unwrap();
        assert_eq!(buffer.len(), 4096);
        let mut reader = std::io::Cursor::new(&buffer);
        let mut key_imported = NvsEncryptionKey::new([0; 64]);
        key_imported.import(&mut reader).unwrap();
        assert_eq!(key_imported.key, key.key);
    }
}

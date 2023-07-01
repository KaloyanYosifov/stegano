use byteorder::ReadBytesExt;
use std::fs::File;
use std::io::Read;
use std::mem::size_of;
use std::path::Path;

#[derive(PartialEq, Eq, Clone, Debug)]
pub enum ContentVersion {
    V2,
    V4,
    V5,
    Unsupported(u8),
}

impl ContentVersion {
    pub fn to_u8(&self) -> u8 {
        match self {
            Self::V2 => 0x02,
            Self::V4 => 0x04,
            Self::V5 => 0x05,
            Self::Unsupported(v) => *v,
        }
    }

    pub fn from_u8(value: u8) -> Self {
        match value {
            0x02 => Self::V2,
            0x04 => Self::V4,
            0x05 => Self::V5,
            b => Self::Unsupported(b),
        }
    }
}

#[derive(Default, Clone, Debug)]
pub struct MessageHeader {
    pub file_size: u64,
    pub encrypted: bool,
}

impl MessageHeader {
    /// # Safety
    /// This function is used to convert message header to bytes
    pub unsafe fn to_u8(&self) -> &[u8] {
        core::slice::from_raw_parts((self as *const Self) as *const u8, size_of::<Self>())
    }
}

type MessageFile = (String, Vec<u8>);

pub struct Message {
    version: ContentVersion,
    header: MessageHeader,
    files: Vec<MessageFile>,
}

// TODO implement Result returning
impl Message {
    pub fn new(version: ContentVersion) -> Self {
        Self {
            version,
            files: Vec::new(),
            header: MessageHeader::default(),
        }
    }

    pub fn new_with_header(header: MessageHeader, version: ContentVersion) -> Self {
        Self {
            header,
            version,
            files: Vec::new(),
        }
    }

    pub fn is_valid(dec: &mut dyn Read) -> bool {
        let version = dec.read_u8().unwrap_or_default();
        let version = ContentVersion::from_u8(version);

        !matches!(version, ContentVersion::Unsupported(_))
    }

    pub fn new_of_files(files: &[&str]) -> Self {
        Self::new_of_files_with_version(files, ContentVersion::V5)
    }

    pub fn new_of_files_with_version(files: &[&str], version: ContentVersion) -> Self {
        let mut m = Self {
            version,
            files: Vec::new(),
            header: MessageHeader::default(),
        };

        files.iter().for_each(|f| {
            m.add_file(f);
        });

        m
    }

    pub fn add_file(&mut self, file: &str) -> &mut Self {
        let mut fd = File::open(file).expect("File was not readable");
        let mut fb: Vec<u8> = Vec::new();

        fd.read_to_end(&mut fb).expect("Failed buffer whole file.");

        let file = Path::new(file).file_name().unwrap().to_str().unwrap();

        self.add_file_data(file, fb);
        // self.files.push((file.to_owned(), fb));

        self
    }

    pub fn add_file_data(&mut self, file: &str, data: Vec<u8>) -> &mut Self {
        let data_len = data.len();
        self.files.push((file.to_owned(), data));

        self.header.file_size += data_len as u64;

        self
    }

    pub fn get_files(&self) -> &Vec<MessageFile> {
        &self.files
    }

    pub fn has_files(&self) -> bool {
        !self.get_files().is_empty()
    }

    pub fn get_version(&self) -> ContentVersion {
        self.version.clone()
    }

    pub fn get_header(&self) -> &MessageHeader {
        &self.header
    }

    // in Bytes
    pub fn get_header_length(&self) -> usize {
        let version_size = 1;

        match self.version {
            ContentVersion::V4 => version_size + 4, // 4 bytes for file size
            ContentVersion::V5 => version_size + size_of::<MessageHeader>(),
            _ => version_size,
        }
    }
}

#[cfg(test)]
mod message_tests {
    use super::*;
    use std::io::{copy, Cursor};
    use zip::write::FileOptions;
    use zip::{CompressionMethod, ZipWriter};

    #[test]
    fn should_create_zip_that_is_windows_compatible() {
        let mut file = File::open("../resources/with_text/hello_world.png").unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();

        let mut out_buf = Vec::new();

        let w = Cursor::new(&mut out_buf);
        let mut zip = ZipWriter::new(w);

        let options = FileOptions::default().compression_method(CompressionMethod::Deflated);

        zip.start_file("hello_world.png", options)
            .unwrap_or_else(|_| panic!("processing file '{}' failed.", "hello_world.png"));

        let mut r = Cursor::new(buf);
        copy(&mut r, &mut zip).expect("Failed to copy data to the zip entry.");

        zip.finish().expect("finish zip failed.");
    }
}

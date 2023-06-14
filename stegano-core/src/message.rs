use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::Path;

use crate::crypto::EncryptDecrypt;
use crate::Result;

#[derive(PartialEq, Eq, Debug)]
pub enum ContentVersion {
    V2,
    V4,
    Unsupported(u8),
}

impl ContentVersion {
    pub fn to_u8(&self) -> u8 {
        match self {
            Self::V2 => 0x02,
            Self::V4 => 0x04,
            Self::Unsupported(v) => *v,
        }
    }

    pub fn from_u8(value: u8) -> Self {
        match value {
            0x02 => Self::V2,
            0x04 => Self::V4,
            b => Self::Unsupported(b),
        }
    }
}

pub struct Message {
    pub header: ContentVersion,
    pub files: Vec<(String, Vec<u8>)>,
}

type MessagePassword = Option<String>;

// TODO implement Result returning
impl Message {
    pub fn of(dec: &mut dyn Read, password: MessagePassword) -> Self {
        let version = dec.read_u8().unwrap_or_default();
        let version = ContentVersion::from_u8(version);

        match version {
            ContentVersion::V2 => Self::new_of_v2(dec, password),
            ContentVersion::V4 => Self::new_of_v4(dec, password),
            ContentVersion::Unsupported(_) => {
                panic!("Seems like you've got an invalid stegano file")
            }
        }
    }

    pub fn is_valid(dec: &mut dyn Read) -> bool {
        let version = dec.read_u8().unwrap_or_default();
        let version = ContentVersion::from_u8(version);

        match version {
            ContentVersion::V2 | ContentVersion::V4 => true,
            ContentVersion::Unsupported(_) => false,
        }
    }

    pub fn new_of_files(files: &[String]) -> Self {
        let mut m = Self::new(ContentVersion::V4);

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
        self.files.push((file.to_owned(), data));

        self
    }

    pub fn empty() -> Self {
        Self::new(ContentVersion::V4)
    }

    fn new(version: ContentVersion) -> Self {
        Message {
            header: version,
            files: Vec::new(),
        }
    }

    fn new_of_v4(r: &mut dyn Read, password: MessagePassword) -> Self {
        let payload_size = r
            .read_u32::<BigEndian>()
            .expect("Failed to read payload size header");

        let mut buf = Vec::new();
        r.take(payload_size as u64)
            .read_to_end(&mut buf)
            .expect("Message read of content version 0x04 failed.");

        Self::new_of(buf, password)
    }

    fn new_of_v2(r: &mut dyn Read, password: MessagePassword) -> Self {
        const EOF: u8 = 0xff;
        let mut buf = Vec::new();
        r.read_to_end(&mut buf)
            .expect("Message read of content version 0x02 failed.");

        let mut eof = 0;
        for (i, b) in buf.iter().enumerate().rev() {
            if *b == EOF {
                eof = i;
                break;
            }
            eof = 0;
        }

        if eof > 0 {
            buf.resize(eof, 0);
        }

        Self::new_of(buf, password)
    }

    fn new_of(mut buf: Vec<u8>, password: MessagePassword) -> Message {
        let mut files = Vec::new();

        if let Some(pass) = password {
            buf = buf.decrypt(&pass).unwrap();
        }

        let mut buf = Cursor::new(buf);

        while let Ok(zip) = zip::read::read_zipfile_from_stream(&mut buf) {
            match zip {
                None => {}
                Some(mut file) => {
                    let mut writer = Vec::new();
                    file.read_to_end(&mut writer)
                        .expect("Failed to read data from inner message structure.");

                    files.push((file.name().to_string(), writer));
                }
            }
        }

        let mut m = Message::new(ContentVersion::V4);
        m.files.append(&mut files);

        m
    }

    // in Bytes
    pub fn get_header_length(&self) -> usize {
        let version_size = 1;

        match self.header {
            ContentVersion::V4 => version_size + 4,
            _ => version_size,
        }
    }

    pub fn get_data(&self, password: MessagePassword) -> Result<Vec<u8>> {
        let mut v = vec![self.header.to_u8()];

        {
            let mut buf = Vec::new();

            {
                let w = std::io::Cursor::new(&mut buf);
                let mut zip = zip::ZipWriter::new(w);

                let options = zip::write::FileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated);

                (self.files)
                    .iter()
                    .map(|(name, buf)| (name, buf))
                    .for_each(|(name, buf)| {
                        zip.start_file(name, options)
                            .unwrap_or_else(|_| panic!("processing file '{name}' failed."));

                        let mut r = std::io::Cursor::new(buf);
                        std::io::copy(&mut r, &mut zip)
                            .expect("Failed to copy data to the zip entry.");
                    });

                zip.finish().expect("finish zip failed.");
            }

            if let Some(pass) = password {
                buf = buf.encrypt(&pass)?;
            }

            if self.header == ContentVersion::V4 {
                v.write_u32::<BigEndian>(buf.len() as u32)
                    .expect("Failed to write the inner message size.");
            }

            v.append(&mut buf);

            if self.header == ContentVersion::V2 {
                v.write_u16::<BigEndian>(0xffff)
                    .expect("Failed to write content format 2 termination.");
            }
        }

        Ok(v)
    }
}

#[cfg(test)]
mod message_tests {
    use super::*;
    use std::fs;
    use std::io::copy;
    use zip::write::FileOptions;
    use zip::{CompressionMethod, ZipWriter};

    fn get_file_content_from_zip(buf: &[u8]) -> Option<Vec<u8>> {
        let mut cursor = Cursor::new(buf);
        let stream = zip::read::read_zipfile_from_stream(&mut cursor);

        match stream {
            Ok(Some(mut file)) => {
                let mut writer = Vec::new();
                file.read_to_end(&mut writer)
                    .expect("Failed to read data from inner message structure.");

                Some(writer)
            }
            _ => None,
        }
    }

    #[test]
    fn should_create_a_message() {
        let files = vec!["../resources/with_text/hello_world.png".to_string()];
        let message = Message::new_of_files(&files);

        assert_eq!(
            message.files.len(),
            1,
            "One file was not there, buffer was broken"
        );
        let (name, _buf) = &message.files[0];
        assert_eq!(
            name, "hello_world.png",
            "One file was not there, buffer was broken"
        );

        let buffer: Vec<u8> = message.get_data(None).unwrap();
        assert_ne!(buffer.len(), 0, "File buffer was empty");
    }

    #[test]
    fn should_create_a_message_with_correct_data_from_added_files() {
        let files = vec!["../resources/with_text/hello_world.png".to_string()];
        let message = Message::new_of_files(&files);
        let mut buffer: Vec<u8> = message.get_data(None).unwrap();
        let file_contents = fs::read(Path::new(&files[0])).unwrap();

        buffer = get_file_content_from_zip(&buffer[message.get_header_length()..]).unwrap();

        assert_eq!(file_contents.len(), buffer.len());
        for i in 0..buffer.len() {
            assert_eq!(file_contents[i], buffer[i])
        }
    }

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

    #[test]
    fn should_create_a_zip_that_is_encrypted() {
        let files = vec!["../resources/with_text/hello_world.png".to_string()];
        let pass = "test";
        let message = Message::new_of_files(&files);
        let mut buffer: Vec<u8> = message.get_data(Some(pass.into())).unwrap();
        let file_contents = fs::read(Path::new(&files[0])).unwrap();

        // we should fail to unzip as the zip is encrypted
        assert!(get_file_content_from_zip(&buffer[message.get_header_length()..]).is_none());

        // decrypt buffer
        buffer = buffer[message.get_header_length()..]
            .decrypt(&pass)
            .unwrap();
        buffer = get_file_content_from_zip(&buffer).unwrap();

        assert_eq!(file_contents.len(), buffer.len());
        for i in 0..buffer.len() {
            assert_eq!(file_contents[i], buffer[i])
        }
    }
}

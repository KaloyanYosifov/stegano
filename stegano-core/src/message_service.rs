use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read};

use crate::crypto::EncryptDecrypt;
use crate::ContentVersion;
use crate::Message;
use crate::Result;

pub struct MessageService;

type MessagePassword = Option<String>;

impl MessageService {
    pub fn create_message_from_data(dec: &mut dyn Read, password: MessagePassword) -> Message {
        let version = dec.read_u8().unwrap_or_default();
        let version = ContentVersion::from_u8(version);

        match version {
            ContentVersion::V2 => Self::new_of_v2(dec, password),
            ContentVersion::V4 => Self::new_of_v4(dec, password),
            ContentVersion::V5 => unimplemented!("Test"),
            ContentVersion::Unsupported(_) => {
                panic!("Seems like you've got an invalid stegano file")
            }
        }
    }

    pub fn generate_zip_file(message: &Message, password: MessagePassword) -> Result<Vec<u8>> {
        let mut v = vec![message.get_version().to_u8()];

        {
            let mut buf = Vec::new();

            {
                let w = std::io::Cursor::new(&mut buf);
                let mut zip = zip::ZipWriter::new(w);

                let options = zip::write::FileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated);

                (message.get_files())
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

            if message.get_version() == ContentVersion::V4 {
                v.write_u32::<BigEndian>(buf.len() as u32)
                    .expect("Failed to write the inner message size.");
            }

            v.append(&mut buf);

            if message.get_version() == ContentVersion::V2 {
                panic!("V2 is not supported anymore!");
            }
        }

        Ok(v)
    }
}

impl MessageService {
    fn new_of_v4(r: &mut dyn Read, password: MessagePassword) -> Message {
        let payload_size = r
            .read_u32::<BigEndian>()
            .expect("Failed to read payload size header");

        let mut buf = Vec::new();
        r.take(payload_size as u64)
            .read_to_end(&mut buf)
            .expect("Message read of content version 0x04 failed.");

        Self::new_of(buf, password)
    }

    fn new_of_v2(r: &mut dyn Read, password: MessagePassword) -> Message {
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

        let mut message = Message::new(ContentVersion::V4);

        for (file, data) in files {
            message.add_file_data(&file, data);
        }

        message
    }
}

#[cfg(test)]
mod message_service_tests {
    use std::io::{Cursor, Read};
    use std::{fs, path::Path};

    use super::MessageService;
    use crate::crypto::EncryptDecrypt;
    use crate::Message;

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
    fn should_generate_a_zip_file_from_message() {
        let files = vec!["../resources/with_text/hello_world.png"];
        let message = Message::new_of_files(&files);

        assert_eq!(
            message.get_files().len(),
            1,
            "One file was not there, buffer was broken"
        );
        let (name, _buf) = &message.get_files()[0];
        assert_eq!(
            name, "hello_world.png",
            "One file was not there, buffer was broken"
        );

        let buffer: Vec<u8> = MessageService::generate_zip_file(&message, None).unwrap();
        assert_ne!(buffer.len(), 0, "File buffer was empty");
    }

    #[test]
    fn should_generate_a_zip_file_with_correct_content_from_message_files() {
        let files = vec!["../resources/with_text/hello_world.png"];
        let message = Message::new_of_files(&files);
        let mut buffer: Vec<u8> = MessageService::generate_zip_file(&message, None).unwrap();
        let file_contents = fs::read(Path::new(&files[0])).unwrap();

        buffer = get_file_content_from_zip(&buffer[message.get_header_length()..]).unwrap();

        assert_eq!(file_contents.len(), buffer.len());
        for i in 0..buffer.len() {
            assert_eq!(file_contents[i], buffer[i])
        }
    }

    #[test]
    fn should_create_a_zip_that_is_encrypted() {
        let files = vec!["../resources/with_text/hello_world.png"];
        let pass = "test";
        let message = Message::new_of_files(&files);
        let mut buffer: Vec<u8> =
            MessageService::generate_zip_file(&message, Some(pass.into())).unwrap();
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

use crate::crypto::EncryptDecrypt;
use crate::ContentVersion;
use crate::Message;
use crate::Result;

use byteorder::{BigEndian, WriteBytesExt};

pub struct MessageService;

type MessagePassword = Option<String>;

impl MessageService {
    pub fn generate_zip_file(message: &Message, password: MessagePassword) -> Result<Vec<u8>> {
        let mut v = vec![message.header.to_u8()];

        {
            let mut buf = Vec::new();

            {
                let w = std::io::Cursor::new(&mut buf);
                let mut zip = zip::ZipWriter::new(w);

                let options = zip::write::FileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated);

                (message.files)
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

            if message.header == ContentVersion::V4 {
                v.write_u32::<BigEndian>(buf.len() as u32)
                    .expect("Failed to write the inner message size.");
            }

            v.append(&mut buf);

            if message.header == ContentVersion::V2 {
                v.write_u16::<BigEndian>(0xffff)
                    .expect("Failed to write content format 2 termination.");
            }
        }

        Ok(v)
    }
}

#[cfg(test)]
mod message_service_tests {
    use std::io::{Cursor, Read};
    use std::{fs, path::Path};
    use zip::write::FileOptions;
    use zip::{CompressionMethod, ZipWriter};

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

        let buffer: Vec<u8> = MessageService::generate_zip_file(&message, None).unwrap();
        assert_ne!(buffer.len(), 0, "File buffer was empty");
    }

    #[test]
    fn should_generate_a_zip_file_with_correct_content_from_message_files() {
        let files = vec!["../resources/with_text/hello_world.png".to_string()];
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
        let files = vec!["../resources/with_text/hello_world.png".to_string()];
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

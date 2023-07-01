use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::Write;
use std::io::{Cursor, Read};
use std::mem::size_of;

use crate::crypto::EncryptDecrypt;
use crate::password_reader::{PasswordReader, PromptPasswordReader};
use crate::Message;
use crate::Result;
use crate::{ContentVersion, MessageHeader};

pub struct MessageService {
    password_reader: Box<dyn PasswordReader>,
}

type MessagePassword = Option<String>;

impl Default for MessageService {
    #[allow(clippy::box_default)]
    fn default() -> Self {
        Self::new_with_password_reader(Box::new(PromptPasswordReader::default()))
    }
}

impl MessageService {
    pub fn new_with_password_reader(password_reader: Box<dyn PasswordReader>) -> Self {
        Self { password_reader }
    }

    pub fn create_message_from_data(&self, dec: &mut dyn Read) -> Result<Message> {
        let version = dec.read_u8().unwrap_or_default();
        let version = ContentVersion::from_u8(version);

        match version {
            ContentVersion::V2 => self.new_of_v2(dec),
            ContentVersion::V4 => self.new_of_v4(dec),
            ContentVersion::V5 => self.new_of_v5(dec),
            ContentVersion::Unsupported(_) => {
                panic!("Seems like you've got an invalid stegano file")
            }
        }
    }

    #[allow(clippy::unused_io_amount)]
    pub fn generate_zip_file(
        &self,
        message: &Message,
        password: MessagePassword,
    ) -> Result<Vec<u8>> {
        let message_version = message.get_version();
        let mut message_header = message.get_header().clone();
        let mut v = vec![message_version.to_u8()];

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

                message_header.encrypted = true;
            }

            match message_version {
                ContentVersion::V4 => v
                    .write_u32::<BigEndian>(buf.len() as u32)
                    .expect("Failed to write the inner message size."),
                ContentVersion::V5 => {
                    message_header.file_size = buf.len() as u64;

                    unsafe {
                        let bytes = message_header.to_u8();

                        v.write(bytes)
                            .expect("Failed to write the inner message size.");
                    }
                }
                _ => {}
            };

            v.append(&mut buf);

            if message_version == ContentVersion::V2 {
                panic!("V2 is not supported anymore!");
            }
        }

        Ok(v)
    }
}

impl MessageService {
    fn new_of_v5(&self, r: &mut dyn Read) -> Result<Message> {
        let mut message_header_in_bytes = [0u8; size_of::<MessageHeader>()];

        r.read_exact(&mut message_header_in_bytes)
            .expect("Failed to read payload size header");

        let message_header: MessageHeader = unsafe { std::mem::transmute(message_header_in_bytes) };
        let mut buf = Vec::new();

        r.take(message_header.file_size)
            .read_to_end(&mut buf)
            .expect("Message read of content version 0x04 failed.");

        self.new_of(buf, message_header)
    }

    fn new_of_v4(&self, r: &mut dyn Read) -> Result<Message> {
        let payload_size = r
            .read_u32::<BigEndian>()
            .expect("Failed to read payload size header");

        let mut buf = Vec::new();
        r.take(payload_size as u64)
            .read_to_end(&mut buf)
            .expect("Message read of content version 0x04 failed.");

        self.new_of(buf, MessageHeader::default())
    }

    fn new_of_v2(&self, r: &mut dyn Read) -> Result<Message> {
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

        self.new_of(buf, MessageHeader::default())
    }

    fn new_of(&self, mut buf: Vec<u8>, message_header: MessageHeader) -> Result<Message> {
        let mut files = Vec::new();
        if message_header.encrypted {
            let password = self
                .password_reader
                .read_password_prompt("Enter decryption password: ")
                .unwrap();

            buf = buf.decrypt(&password)?;
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

        let mut message = Message::new_with_header(message_header);

        for (file, data) in files {
            message.add_file_data(&file, data);
        }

        Ok(message)
    }
}

#[cfg(test)]
mod message_service_tests {
    use std::io::{Cursor, Read};
    use std::{fs, path::Path};

    use super::MessageService;
    use crate::crypto::EncryptDecrypt;
    use crate::password_reader::PredefinedPasswordReader;
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

        let buffer: Vec<u8> = MessageService::default()
            .generate_zip_file(&message, None)
            .unwrap();
        assert_ne!(buffer.len(), 0, "File buffer was empty");
    }

    #[test]
    fn should_generate_a_zip_file_with_correct_content_from_message_files() {
        let files = vec!["../resources/with_text/hello_world.png"];
        let message = Message::new_of_files(&files);
        let mut buffer: Vec<u8> = MessageService::default()
            .generate_zip_file(&message, None)
            .unwrap();
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
        let mut buffer: Vec<u8> = MessageService::default()
            .generate_zip_file(&message, Some(pass.into()))
            .unwrap();
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

    #[test]
    fn should_create_a_message_from_data() {
        let files = vec!["../resources/with_text/hello_world.png"];
        let message = Message::new_of_files(&files);
        let buffer: Vec<u8> = MessageService::default()
            .generate_zip_file(&message, None)
            .unwrap();
        let parsed_message = MessageService::default()
            .create_message_from_data(&mut Cursor::new(buffer))
            .unwrap();

        assert_eq!(parsed_message.get_version(), message.get_version());
        assert_eq!(
            parsed_message.get_header_length(),
            message.get_header_length()
        );
    }

    #[test]
    fn should_create_a_message_from_encrypted_data() {
        let files = vec!["../resources/with_text/hello_world.png"];
        let pass = Some("Test".into());
        let message = Message::new_of_files(&files);
        let buffer: Vec<u8> = MessageService::default()
            .generate_zip_file(&message, pass.clone())
            .unwrap();
        let message_service = MessageService::new_with_password_reader(Box::new(
            PredefinedPasswordReader::new(pass.clone()),
        ));
        let parsed_message = message_service
            .create_message_from_data(&mut Cursor::new(buffer))
            .unwrap();

        assert_eq!(parsed_message.get_version(), message.get_version());
        assert_eq!(
            parsed_message.get_header_length(),
            message.get_header_length()
        );
    }

    #[test]
    fn fails_creating_a_message_from_data_if_wrong_decryption_password_is_used() {
        let files = vec!["../resources/with_text/hello_world.png"];
        let pass = Some("Test".into());
        let message = Message::new_of_files(&files);
        let buffer: Vec<u8> = MessageService::default()
            .generate_zip_file(&message, pass.clone())
            .unwrap();
        let message_service = MessageService::new_with_password_reader(Box::new(
            PredefinedPasswordReader::new(Some("Test2".into())),
        ));
        let result = message_service.create_message_from_data(&mut Cursor::new(buffer));

        assert!(result.is_err());
        matches!(
            result.err().unwrap(),
            crate::SteganoError::CannotEncryptData
        );
    }

    #[test]
    #[should_panic(expected = "Seems like you've got an invalid stegano file")]
    fn fails_creating_a_message_from_data_if_version_is_not_supported() {
        let files = vec!["../resources/with_text/hello_world.png"];
        let message = Message::new_of_files(&files);
        let mut buffer: Vec<u8> = MessageService::default()
            .generate_zip_file(&message, None)
            .unwrap();

        // Change version
        buffer[0] = 0x01;

        MessageService::default()
            .create_message_from_data(&mut Cursor::new(buffer))
            .unwrap();
    }
}

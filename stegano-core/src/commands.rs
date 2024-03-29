use crate::media::audio::wav_iter::AudioWavIter;
use crate::media::image::LsbCodec;
use crate::message_service::MessageService;
use crate::universal_decoder::{Decoder, OneBitUnveil};
use crate::{CodecOptions, Media, Message, RawMessage, SteganoError, UnveilOptions};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

pub fn unveil(
    secret_media: &Path,
    destination: &Path,
    opts: &UnveilOptions,
) -> Result<(), SteganoError> {
    let media = Media::from_file(secret_media)?;

    let message = match media {
        Media::Image(image) => {
            let mut decoder = LsbCodec::decoder(&image, &opts.codec_options);

            MessageService::default().create_message_from_data(&mut decoder)?
        }
        Media::Audio(audio) => {
            let mut decoder = Decoder::new(AudioWavIter::new(audio.1.into_iter()), OneBitUnveil);

            MessageService::default().create_message_from_data(&mut decoder)?
        }
    };

    if !message.has_files() {
        return Err(SteganoError::NoSecretData);
    }

    let files = message.get_files();

    for (file_name, buf) in files.iter().map(|(file_name, buf)| {
        let file = Path::new(file_name).file_name().unwrap().to_str().unwrap();

        (file, buf)
    }) {
        if !destination.exists() {
            fs::create_dir_all(destination)?;
        }

        let target_file = destination.join(file_name);
        let mut target_file =
            File::create(target_file).map_err(|source| SteganoError::WriteError { source })?;

        target_file
            .write_all(buf.as_slice())
            .map_err(|source| SteganoError::WriteError { source })?;
    }

    Ok(())
}

/// unveil all raw data, no content format interpretation is happening.
/// Just a raw binary dump of the data gathered by the LSB algorithm.
pub fn unveil_raw(secret_media: &Path, destination_file: &Path) -> Result<(), SteganoError> {
    let media = Media::from_file(secret_media)?;

    match media {
        Media::Image(image) => {
            let mut decoder = LsbCodec::decoder(&image, &CodecOptions::default());
            let msg = RawMessage::of(&mut decoder);
            let mut destination_file = File::create(destination_file)
                .map_err(|source| SteganoError::WriteError { source })?;

            destination_file
                .write_all(msg.content.as_slice())
                .map_err(|source| SteganoError::WriteError { source })
        }
        Media::Audio(audio) => {
            let mut decoder = Decoder::new(AudioWavIter::new(audio.1.into_iter()), OneBitUnveil);

            let msg = RawMessage::of(&mut decoder);
            let mut destination_file = File::create(destination_file)
                .map_err(|source| SteganoError::WriteError { source })?;

            destination_file
                .write_all(msg.content.as_slice())
                .map_err(|source| SteganoError::WriteError { source })
        }
    }
}

/// unveil all raw data, no content format interpretation is happening.
/// Just a raw binary dump of the data gathered by the LSB algorithm.
pub fn check_files(files: Vec<&Path>) -> Result<Vec<&Path>, SteganoError> {
    let mut files_with_secrets = vec![];

    for file in files {
        let media = Media::from_file(file);

        if media.is_err() {
            continue;
        }

        match media.unwrap() {
            Media::Image(image) => {
                let mut decoder = LsbCodec::decoder(&image, &CodecOptions::default());

                if Message::is_valid(&mut decoder) {
                    files_with_secrets.push(file);
                }
            }
            Media::Audio(audio) => {
                let mut decoder =
                    Decoder::new(AudioWavIter::new(audio.1.into_iter()), OneBitUnveil);

                if Message::is_valid(&mut decoder) {
                    files_with_secrets.push(file);
                }
            }
        };
    }

    Ok(files_with_secrets)
}

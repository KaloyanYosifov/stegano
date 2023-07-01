use clap::{crate_authors, crate_description, crate_version, Arg, ArgMatches, Command};

use std::fs;
use std::path::{Path, PathBuf};
use stegano_core::commands::{check_files, unveil, unveil_raw};
use stegano_core::*;

fn main() -> Result<()> {
    let matches = Command::new("Stegano CLI")
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .arg_required_else_help(true)
        .subcommand(
            Command::new("hide")
                .about("Hides data in PNG images and WAV audio files")
                .arg(
                    Arg::new("media")
                        .short('i')
                        .long("in")
                        .value_name("media file")
                        .required(true)
                        .help("Media file such as PNG image or WAV audio file, used readonly."),
                )
                .arg(
                    Arg::new("write_to_file")
                        .short('o')
                        .long("out")
                        .value_name("output image file")
                        .required(true)
                        .help("Final image will be stored as file"),
                )
                .arg(
                    Arg::new("data_file")
                        .short('d')
                        .long("data")
                        .value_name("data file")
                        .required_unless_present("message")
                        .num_args(1..100)
                        .help("File(s) to hide in the image"),
                )
                .arg(
                    Arg::new("message")
                        .short('m')
                        .long("message")
                        .value_name("text message")
                        .required(false)
                        .help("A text message that will be hidden"),
                )
                .arg(
                    Arg::new("encrypt")
                        .short('e')
                        .long("encrypt")
                        .required(false)
                        .num_args(0)
                        .help("Option to encrypt data"),
                ),
        )
        .subcommand(
            Command::new("unveil")
                .about("Unveils data from PNG images")
                .arg(
                    Arg::new("input_image")
                        .short('i')
                        .long("in")
                        .value_name("image source file")
                        .required(true)
                        .help("Source image that contains secret data"),
                )
                .arg(
                    Arg::new("output_folder")
                        .short('o')
                        .long("out")
                        .value_name("output folder")
                        .required(true)
                        .help("Final data will be stored in that folder"),
                ),
        )
        .subcommand(
            Command::new("unveil-raw")
                .about("Unveils raw data in PNG images")
                .arg(
                    Arg::new("input_image")
                        .short('i')
                        .long("in")
                        .value_name("image source file")
                        .required(true)
                        .help("Source image that contains secret data"),
                )
                .arg(
                    Arg::new("output_file")
                        .short('o')
                        .long("out")
                        .value_name("output file")
                        .required(true)
                        .help("Raw data will be stored as binary file"),
                ),
        )
        .subcommand(
            Command::new("check")
                .about("Checks if file or files in directory are secrets")
                .arg(
                    Arg::new("input")
                        .short('i')
                        .value_name("file or files")
                        .required(true)
                        .help("Choose files or multiple files"),
                ),
        )
        .arg(
            Arg::new("color_step_increment")
                .long("x-color-step-increment")
                .value_name("color channel step increment")
                .default_value("1")
                .required(false)
                .help("Experimental: image color channel step increment"),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("hide", m)) => {
            let opts = get_hide_options(&m);
            let codec_options = get_codec_options(CodecOptions::default(), &matches);
            let mut s = SteganoCore::encoder_with_options(codec_options);

            s.use_media(m.get_one::<String>("media").unwrap())?
                .write_to(m.get_one::<String>("write_to_file").unwrap());

            if let Some(_) = m.get_one::<String>("message") {
                panic!("Unsopported bullshit!");
            }

            if let Some(files) = m.get_many::<String>("data_file") {
                s.hide(files.map(|f| &**f).collect(), &opts);
            } else {
                panic!("No files entered!");
            }
        }
        Some(("unveil", m)) => {
            let mut opts = get_unveil_options(&m);
            opts.codec_options = get_codec_options(CodecOptions::default(), &matches);

            unveil(
                Path::new(m.get_one::<String>("input_image").unwrap()),
                Path::new(m.get_one::<String>("output_folder").unwrap()),
                &opts,
            )?;
        }
        Some(("unveil-raw", m)) => {
            unveil_raw(
                Path::new(m.get_one::<String>("input_image").unwrap()),
                Path::new(m.get_one::<String>("output_folder").unwrap()),
            )?;
        }
        Some(("check", m)) => {
            let input = m.get_one::<String>("input").unwrap();
            let path = Path::new(input);
            let mut paths: Vec<PathBuf> = vec![];

            if path.is_dir() {
                let files = fs::read_dir(path)?;
                paths = files
                    .map(|file| file.unwrap().path())
                    .filter(|file| file.is_file())
                    .collect();
            } else {
                paths.push(path.to_path_buf());
            }

            let paths_only = paths.iter().map(|path| path.as_path()).collect();
            let files_with_secrets = check_files(paths_only)?;

            if files_with_secrets.len() == 0 {
                println!("No secrets found");

                return Ok(());
            }

            println!("Files With secrets: ");

            files_with_secrets
                .iter()
                .for_each(|file| println!("{}", file.to_str().unwrap()));
        }
        _ => {}
    }

    Ok(())
}

fn get_hide_options(args: &ArgMatches) -> HideOptions {
    let mut opts = HideOptions::default();

    if *args.get_one::<bool>("encrypt").unwrap() {
        opts.encrypt = true;
    }

    opts
}

fn get_unveil_options(args: &ArgMatches) -> UnveilOptions {
    let mut opts = UnveilOptions::default();
    opts.codec_options = get_codec_options(opts.codec_options, args);

    opts
}

fn get_codec_options(mut opts: CodecOptions, args: &ArgMatches) -> CodecOptions {
    if args.contains_id("color_step_increment") {
        opts.color_channel_step_increment = args
            .get_one::<String>("color_step_increment")
            .unwrap()
            .parse()
            .unwrap();
    }
    opts
}

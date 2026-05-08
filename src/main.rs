use std::io::{self};

use clap::{CommandFactory, Parser, Subcommand, ValueHint};
use clap_complete::{Shell, generate};

mod constant;
mod file;
mod prime_number;
mod rsa;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    GenCompletion {
        #[arg(value_name = "SHELL")]
        shell: Shell,
    },
    Keygen {
        #[arg(short, long, value_hint = ValueHint::FilePath)]
        output: String,

        #[arg(short, long, default_value = "1024")]
        bits: usize,
    },

    Encrypt {
        #[arg(short, long, value_hint = ValueHint::FilePath)]
        key: String,

        #[arg(short, long, value_hint = ValueHint::FilePath)]
        output: Option<String>,

        #[arg(value_hint = ValueHint::FilePath)]
        input: Option<String>,
    },

    Decrypt {
        #[arg(short, long, value_hint = ValueHint::FilePath)]
        key: String,

        #[arg(short, long, value_hint = ValueHint::FilePath)]
        output: Option<String>,

        #[arg(value_hint = ValueHint::FilePath)]
        input: Option<String>,
    },
}

fn main() -> std::io::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { output, bits } => {
            let keypair = rsa::keygen(bits as u64);
            file::save_key(&output, &keypair)?;
        }

        Commands::Encrypt { key, input, output } => {
            let pubkey = file::read_public_key(&key)?;

            let mut input_buf = file::open_input(input.as_deref())?;
            let mut output_buf = file::open_output(output.as_deref())?;

            rsa::process_encrypt(&mut input_buf, &mut output_buf, &pubkey)?;
        }

        Commands::Decrypt { key, input, output } => {
            let privkey = file::read_private_key(&key)?;

            let mut input_buf = file::open_input(input.as_deref())?;
            let mut output_buf = file::open_output(output.as_deref())?;

            rsa::process_decrypt(&mut input_buf, &mut output_buf, &privkey)?;
        }

        Commands::GenCompletion { shell } => {
            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();

            generate(shell, &mut cmd, name, &mut io::stdout());
        }
    }

    Ok(())
}

use clap::{Parser, Subcommand};

mod constant;
mod file;
mod prime_number;
mod rsa;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Keygen {
        #[arg(short, long)]
        output: String,

        #[arg(short, long, default_value = "1024")]
        bits: usize,
    },

    Encrypt {
        #[arg(short, long)]
        key: String,

        #[arg(short, long)]
        output: Option<String>,

        input: Option<String>,
    },

    Decrypt {
        #[arg(short, long)]
        key: String,

        #[arg(short, long)]
        output: Option<String>,

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
            rsa::process_encrypt(input.as_deref(), output.as_deref(), &pubkey)?;
        }

        Commands::Decrypt { key, input, output } => {
            let privkey = file::read_private_key(&key)?;
            rsa::process_decrypt(input.as_deref(), output.as_deref(), &privkey)?;
        }
    }

    Ok(())
}

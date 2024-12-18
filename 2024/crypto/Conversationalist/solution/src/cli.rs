use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "gcm_solver", about = "Break AES-GCM with a nonce reuse")]
pub struct Cli {
    /// Three messages (mini header : ciphertext) in the cocoon format
    #[clap(short, long, num_args = 3, required = true)]
    pub messages: Vec<String>,

    /// Ciphertext to forge an authentication tag for (in hex)
    #[clap(short, long, required = true)]
    pub forged_ciphertext: String,
}

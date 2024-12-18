use clap::Parser;
use solve::{cli::Cli, Solver};

fn main() {
    let args = Cli::parse();

    let messages = args
        .messages
        .iter()
        .map(|m| m.as_str())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let solver = Solver::new(messages);

    let solved = solver.solve().unwrap();
    let message = solved.forge_message(&hex::decode(&args.forged_ciphertext).unwrap());

    println!("{message}");
}

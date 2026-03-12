use crate::file::{read_key, save_key};

mod constant;
mod prime_number;
mod rsa;
mod file;

fn main() {
    let keypair = rsa::keygen::generate(1024);
    println!("{keypair:#?}");
    save_key("test", keypair).unwrap();
    let key = read_key("test").unwrap();
    println!("{key:#?}");
}

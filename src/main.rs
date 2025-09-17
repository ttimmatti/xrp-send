use dotenv::dotenv;
use std::env;

mod keypair;

fn main() {
    dotenv().ok();
    let secret_str = env::var("SECRET_STR").expect("SECRET_STR must be set in .env");
    let address = env::var("ADDRESS").expect("ADDRESS must be set in .env");
    println!("Expected address: {:?}", address);

    let keypair = keypair::KeypairEd25519::from_secret_str(&secret_str);

    let derived_address = keypair.derive_address();
    println!("Derived address: {:?}", derived_address);

    assert_eq!(
        derived_address, address,
        "Derived ed25519 address is not correct"
    );
    println!("Derived ed25519 address is correct");
}

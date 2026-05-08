use std::env;
use std::fs;
use std::process::Command;

fn get_bin() -> String {
    env!("CARGO_BIN_EXE_rust-rsa").to_string()
}

#[test]
fn test_cli_keygen_encrypt_decrypt() {
    let bin = get_bin();
    let tmp_dir = env::temp_dir();
    let pid = std::process::id();

    let key_prefix = tmp_dir.join(format!("int_key_{}", pid));
    let key_str = key_prefix.to_str().unwrap();

    let input_path = tmp_dir.join(format!("int_input_{}.txt", pid));
    let enc_path = tmp_dir.join(format!("int_enc_{}.bin", pid));
    let dec_path = tmp_dir.join(format!("int_dec_{}.txt", pid));

    let input_str = input_path.to_str().unwrap();
    let enc_str = enc_path.to_str().unwrap();
    let dec_str = dec_path.to_str().unwrap();

    let msg = b"Integration test secret message.";
    fs::write(input_str, msg).unwrap();

    // 1. Keygen
    let status = Command::new(&bin)
        .arg("keygen")
        .arg("-o")
        .arg(key_str)
        .arg("-b")
        .arg("512")
        .status()
        .expect("Failed to execute keygen");
    assert!(status.success());

    // 2. Encrypt
    let status = Command::new(&bin)
        .arg("encrypt")
        .arg("-k")
        .arg(format!("{}.pub", key_str))
        .arg(input_str)
        .arg("-o")
        .arg(enc_str)
        .status()
        .expect("Failed to execute encrypt");
    assert!(status.success());

    // 3. Decrypt
    let status = Command::new(&bin)
        .arg("decrypt")
        .arg("-k")
        .arg(key_str)
        .arg(enc_str)
        .arg("-o")
        .arg(dec_str)
        .status()
        .expect("Failed to execute decrypt");
    assert!(status.success());

    // Check if decrypted matches original
    let decrypted_msg = fs::read(dec_str).expect("Failed to read decrypted file");
    assert_eq!(msg.to_vec(), decrypted_msg);

    // cleanup
    let _ = fs::remove_file(format!("{}.pub", key_str));
    let _ = fs::remove_file(key_str);
    let _ = fs::remove_file(input_str);
    let _ = fs::remove_file(enc_str);
    let _ = fs::remove_file(dec_str);
}

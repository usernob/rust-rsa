use std::{
    fs::File,
    io::{self, BufRead, BufReader, BufWriter, Write},
};

use num_bigint::BigUint;

use crate::{
    constant::{CHUNK_WITDH, PRIVATE_HEADER, PUBLIC_HEADER, SEPARATOR},
    rsa::KeyPair,
};

fn wrap_write<W: Write>(writer: &mut W, s: &str) -> io::Result<()> {
    let mut tmp = s.as_bytes().chunks(CHUNK_WITDH);
    while let Some(chunk) = tmp.next() {
        writer.write_all(chunk)?;
        writer.write_all(b"\n")?;
    }
    Ok(())
}

fn write(path: &str, header: &str, a: &BigUint, b: &BigUint) -> io::Result<()> {
    let file: File = File::create(path)?;
    let mut writer: BufWriter<File> = BufWriter::new(file);

    // convert to hexadecimal
    let a_str: String = a.to_str_radix(16);
    let b_str: String = b.to_str_radix(16);

    writer.write_all(header.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.write_all(SEPARATOR.as_bytes())?;
    writer.write_all(b"\n")?;

    wrap_write(&mut writer, &a_str.to_uppercase())?;
    writer.write_all(SEPARATOR.as_bytes())?;
    writer.write_all(b"\n")?;

    wrap_write(&mut writer, &b_str.to_uppercase())?;
    writer.write_all(SEPARATOR.as_bytes())?;
    writer.flush()?;
    Ok(())
}

fn expect_line<I>(lines: &mut I, expected: &str) -> io::Result<()>
where
    I: Iterator<Item = io::Result<String>>,
{
    let line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "UnexpectedEof"))??;

    if line != expected {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid format"));
    }

    Ok(())
}

fn read_biguint<I>(lines: &mut I) -> io::Result<BigUint>
where
    I: Iterator<Item = io::Result<String>>,
{
    let mut buf: String = String::with_capacity(1024);
    for line in lines {
        let line = line?;
        if &line == SEPARATOR {
            return BigUint::parse_bytes(buf.as_bytes(), 16)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid BigUint"));
        }
        buf.push_str(&line);
    }
    Err(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "Missing separator",
    ))
}

fn read(path: &str, header: &str) -> io::Result<(BigUint, BigUint)> {
    let file: File = File::open(path)?;
    let reader: BufReader<File> = BufReader::new(file);
    let mut lines = reader.lines();

    expect_line(&mut lines, header)?;
    expect_line(&mut lines, SEPARATOR)?;
    let a: BigUint = read_biguint(&mut lines)?;
    let b: BigUint = read_biguint(&mut lines)?;

    Ok((a, b))
}

pub fn save_key(filename: &str, key: KeyPair) -> io::Result<()> {
    let public_path: String = format!("{}.pub", filename);
    let private_path: &str = filename;
    write(&public_path, PUBLIC_HEADER, &key.n, &key.e)?;
    write(&private_path, PRIVATE_HEADER, &key.n, &key.d)?;
    Ok(())
}

pub fn read_key(filename: &str) -> io::Result<KeyPair> {
    let public_path: String = format!("{}.pub", filename);
    let private_path: &str = filename;
    let (_n, e) = read(&public_path, PUBLIC_HEADER)?;
    let (n, d) = read(&private_path, PRIVATE_HEADER)?;
    Ok(KeyPair { n, e, d })
}

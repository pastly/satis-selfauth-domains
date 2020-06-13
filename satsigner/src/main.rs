use std::env;
use std::fs::File;
use std::io::{Error as IoError, Read, Write as IoWrite, ErrorKind};

use std::time::SystemTime;

use std::fmt::Write as FmtWrite;
use std::str;

use std::fs::read_to_string;

use std::path::Path;

use rand::prelude::*;

extern crate base64;
extern crate ed25519_dalek;

use ed25519_dalek::ExpandedSecretKey;
use ed25519_dalek::PublicKey;
use ed25519_dalek::Signature;

const KEY_FILE_PREFIX: &str = "hs_ed25519_";
const SECRET_KEY_FILE_SUFFIX: &str = "secret_key";
const PUBLIC_KEY_FILE_SUFFIX: &str = "public_key";
const SATTESTATION_CSV: &str = "sattestation.csv";

fn open_key_file(file: String) -> Result<File, IoError> {
    File::open(file)
}

fn read_from_file(file: &mut File, mut output: &mut Vec<u8>) -> Result<usize, IoError> {
    file.read_to_end(&mut output)
}

fn parse_tagged_key(typestring: &str, tag: &str, raw_key: &Vec<u8>, keylen: usize) -> Result<Vec<u8>, IoError> {
    const PREFIX_PREFIX: &str = "== ";
    const PREFIX_SUFFIX: &str = " ==";
    const TAG_SEPARATOR: &str = ": ";

    if raw_key.len() <= PREFIX_PREFIX.len() {
        return Err(IoError::new(ErrorKind::InvalidData, "invalid length: less than prefix"));
    }

    let mut raw_key_offset = 0;
    for i in 0..(PREFIX_PREFIX.len()) {
        let raw_key_byte = raw_key.get(raw_key_offset).unwrap();
        let prefix_prefix_byte = PREFIX_PREFIX.as_bytes().get(i).unwrap();
        if raw_key_byte != prefix_prefix_byte {
            return Err(IoError::new(ErrorKind::InvalidData, "invalid prefix prefix"));
        }
        raw_key_offset += 1;
    }

    if raw_key.len() <= raw_key_offset + typestring.len() {
        return Err(IoError::new(ErrorKind::InvalidData, "invalid length: less than typestring"));
    }
    for i in 0..(typestring.len()) {
        let raw_key_byte = raw_key.get(raw_key_offset).unwrap();
        let typestring_byte = typestring.as_bytes().get(i).unwrap();
        if raw_key_byte != typestring_byte {
            let msg = format!("invalid typestring at {}, expected {}, found {}", raw_key_offset, typestring_byte, raw_key_byte);
            return Err(IoError::new(ErrorKind::InvalidData, msg));
        }
        raw_key_offset += 1;
    }

    if raw_key.len() <= raw_key_offset + TAG_SEPARATOR.len() {
        return Err(IoError::new(ErrorKind::InvalidData, "invalid length: less than tag separator"));
    }
    for i in 0..(TAG_SEPARATOR.len()) {
        let raw_key_byte = raw_key.get(raw_key_offset).unwrap();
        let tag_separator_byte = TAG_SEPARATOR.as_bytes().get(i).unwrap();
        if raw_key_byte != tag_separator_byte {
            let msg = format!("invalid tag separator at {}, expected {}, found {}", raw_key_offset, tag_separator_byte, raw_key_byte);
            return Err(IoError::new(ErrorKind::InvalidData, msg));
        }
        raw_key_offset += 1;
    }

    if raw_key.len() <= raw_key_offset + tag.len() {
        return Err(IoError::new(ErrorKind::InvalidData, "invalid length: less than tag"));
    }
    for i in 0..(tag.len()) {
        let raw_key_byte = raw_key.get(raw_key_offset).unwrap();
        let tag_byte = tag.as_bytes().get(i).unwrap();
        if raw_key_byte != tag_byte {
            let msg = format!("invalid tag at {}, expected {}, found {}", raw_key_offset, tag_byte, raw_key_byte);
            return Err(IoError::new(ErrorKind::InvalidData, msg));
        }
        raw_key_offset += 1;
    }

    if raw_key.len() <= raw_key_offset + PREFIX_SUFFIX.len() {
        return Err(IoError::new(ErrorKind::InvalidData, "invalid length: less than prefix suffix"));
    }
    for i in 0..(PREFIX_SUFFIX.len()) {
        let raw_key_byte = raw_key.get(raw_key_offset).unwrap();
        let prefix_suffix_byte = PREFIX_SUFFIX.as_bytes().get(i).unwrap();
        if raw_key_byte != prefix_suffix_byte {
            let msg = format!("invalid prefix suffix at {}, expected {}, found {}", raw_key_offset, prefix_suffix_byte, raw_key_byte);
            return Err(IoError::new(ErrorKind::InvalidData, msg));
        }
        raw_key_offset += 1;
    }
    if raw_key_offset != 32 {
        for i in raw_key_offset..32 {
            if raw_key.get(i) != Some(&0) {
                let msg = format!("Expected 0x0 padding at {}, but found {}", i, raw_key.get(i).unwrap());
                return Err(IoError::new(ErrorKind::InvalidData, msg));
            }
            raw_key_offset += 1;
        }
    }

    let mut key = Vec::new();
    for e in raw_key[32..].iter() {
        key.push(*e);
    }

    if key.len() != keylen {
        let msg = format!("Expected secret key of {} bytes, but found {}", keylen, key.len());
        return Err(IoError::new(ErrorKind::InvalidData, msg));
    }

    Ok(key)
}

fn parse_secret_key(raw_key: &Vec<u8>) -> Result<Vec<u8>, IoError> {
    const PREFIX_PREFIX: &str = "== ";
    const PREFIX_SUFFIX: &str = " ==";
    const TYPESTRING: &str = "ed25519v1-secret";
    const TAG_SEPARATOR: &str = ": ";
    const TAG: &str = "type0";

    if raw_key.len() <= PREFIX_PREFIX.len() {
        return Err(IoError::new(ErrorKind::InvalidData, "invalid length: less than prefix"));
    }

    let mut raw_key_offset = 0;
    for i in 0..(PREFIX_PREFIX.len()) {
        let raw_key_byte = raw_key.get(raw_key_offset).unwrap();
        let prefix_prefix_byte = PREFIX_PREFIX.as_bytes().get(i).unwrap();
        if raw_key_byte != prefix_prefix_byte {
            return Err(IoError::new(ErrorKind::InvalidData, "invalid prefix prefix"));
        }
        raw_key_offset += 1;
    }

    if raw_key.len() <= raw_key_offset + TYPESTRING.len() {
        return Err(IoError::new(ErrorKind::InvalidData, "invalid length: less than typestring"));
    }
    for i in 0..(TYPESTRING.len()) {
        let raw_key_byte = raw_key.get(raw_key_offset).unwrap();
        let typestring_byte = TYPESTRING.as_bytes().get(i).unwrap();
        if raw_key_byte != typestring_byte {
            let msg = format!("invalid typestring at {}, expected {}, found {}", raw_key_offset, typestring_byte, raw_key_byte);
            return Err(IoError::new(ErrorKind::InvalidData, msg));
        }
        raw_key_offset += 1;
    }

    if raw_key.len() <= raw_key_offset + TAG_SEPARATOR.len() {
        return Err(IoError::new(ErrorKind::InvalidData, "invalid length: less than tag separator"));
    }
    for i in 0..(TAG_SEPARATOR.len()) {
        let raw_key_byte = raw_key.get(raw_key_offset).unwrap();
        let tag_separator_byte = TAG_SEPARATOR.as_bytes().get(i).unwrap();
        if raw_key_byte != tag_separator_byte {
            let msg = format!("invalid tag separator at {}, expected {}, found {}", raw_key_offset, tag_separator_byte, raw_key_byte);
            return Err(IoError::new(ErrorKind::InvalidData, msg));
        }
        raw_key_offset += 1;
    }

    if raw_key.len() <= raw_key_offset + TAG.len() {
        return Err(IoError::new(ErrorKind::InvalidData, "invalid length: less than tag"));
    }
    for i in 0..(TAG.len()) {
        let raw_key_byte = raw_key.get(raw_key_offset).unwrap();
        let tag_byte = TAG.as_bytes().get(i).unwrap();
        if raw_key_byte != tag_byte {
            let msg = format!("invalid tag at {}, expected {}, found {}", raw_key_offset, tag_byte, raw_key_byte);
            return Err(IoError::new(ErrorKind::InvalidData, msg));
        }
        raw_key_offset += 1;
    }

    if raw_key.len() <= raw_key_offset + PREFIX_SUFFIX.len() {
        return Err(IoError::new(ErrorKind::InvalidData, "invalid length: less than prefix suffix"));
    }
    for i in 0..(PREFIX_SUFFIX.len()) {
        let raw_key_byte = raw_key.get(raw_key_offset).unwrap();
        let prefix_suffix_byte = PREFIX_SUFFIX.as_bytes().get(i).unwrap();
        if raw_key_byte != prefix_suffix_byte {
            let msg = format!("invalid prefix suffix at {}, expected {}, found {}", raw_key_offset, prefix_suffix_byte, raw_key_byte);
            return Err(IoError::new(ErrorKind::InvalidData, msg));
        }
        raw_key_offset += 1;
    }
    if raw_key_offset != 32 {
        for i in raw_key_offset..32 {
            if raw_key.get(i) != Some(&0) {
                let msg = format!("Expected 0x0 padding at {}, but found {}", i, raw_key.get(i).unwrap());
                return Err(IoError::new(ErrorKind::InvalidData, msg));
            }
            raw_key_offset += 1;
        }
    }

    let mut key = Vec::new();
    for e in raw_key[32..].iter() {
        key.push(*e);
    }

    if key.len() != 64 {
        let msg = format!("Expected secret key of 64 bytes, but found {}", key.len());
        return Err(IoError::new(ErrorKind::InvalidData, msg));
    }

    Ok(key)
}

fn read_key(path: &str) -> Result<Vec<u8>, IoError> {
    match read_to_string(path.clone()) {
        Ok(s) => Ok(Vec::from(s.as_bytes())),
        Err(e) => {
            //println!("Error reading file: {}: {:?}", path, e);
            if e.kind() != ErrorKind::InvalidData {
                return Err(e);
            }
 
            let mut pk_file: File = match open_key_file(path.to_string().clone()) {
                Ok(v) => v,
                Err(e) => {
                    println!("Error opening file: {}: {:?}", path, e);
                    return Err(e);
                },
            };
            let mut raw_key = Vec::new();
            let raw_key_len = match read_from_file(&mut pk_file, &mut raw_key) {
                Ok(s) => s,
                Err(e) => {
                    println!("Error reading file: {}: {:?}", path, e);
                    return Err(e);
                },
            };
            if raw_key_len == 0 {
                println!("File exists but it is empty: {}", path);
            }
            Ok(raw_key)
        },
    }
}

fn read_sattestation(path: &str) -> Result<String, IoError> {
    match read_to_string(path.clone()) {
        Ok(s) => Ok(s),
        Err(e) => {
            println!("Error reading file: {}: {:?}", path, e);
            return Err(e);
        },
    }
}

fn print_sat_token_content(indent: &str, sattestee_token: &Vec<&str>) -> String {
    // Strip leading and trailing '{' and '}'
    let mut content = String::new();
    sattestee_token.iter().filter(|&v| v != &"}" || v != &"{").map(|&v| v.replace("=", "\": \"")).for_each(|v| write!(&mut content, "{}\"{}\",\n", indent, v).unwrap());
    // Truncate the final ',' (pop the final new line, and then re-add it)
    content.pop();
    content.pop();
    content.push_str("\n");
    content
}

fn construct_sat_token(sattestee: &Vec<&str>) -> Result<String, IoError> {
    if sattestee.len() != 5 {
      return Err(IoError::new(ErrorKind::InvalidData, "Sattestee invalid length".to_string()));
    }
    let mut sat = String::new();
    sattestee.iter().map(|&v| v.replace("=", "\":\"")).for_each(|v| write!(&mut sat, "\"{}\",", v).unwrap());
    // Truncate the final ','
    sat.pop();
    //sat.push_str(&format!("{{"\"sattestee\":   \"{}\",\n", sat_indent, sattestee[0]));
    //sat.push_str(&format!("{}  \"onion\":       \"{}\",\n", sat_indent, sattestee[1]));
    //sat.push_str(&format!("{}  \"labels\":      \"{{{}}}\",\n", sat_indent, sattestee[2]));
    //sat.push_str(&format!("{}  \"valid_after\": \"{}\"\n", sat_indent, sattestee[3]));
    //sat.push_str(&format!("{}}}", sat_indent));
    //Ok(sat_list.push(sat))
    Ok(sat)
}


fn construct_sat_token_header(hostname: &str, onionaddr: &str, sattestor_labels: &str, indentation: &str, new_line: &str) -> String {
  let mut header = String::new();
  write!(&mut header, "{}\"sat_list_version\":\"1\",{}", indentation, new_line)
      .expect("Writing header failed");
  write!(&mut header, "{}\"sattestor_domain\":\"{}\",{}", indentation, hostname, new_line)
      .expect("Writing header failed");
  write!(&mut header, "{}\"sattestor_onion\":\"{}\",{}", indentation, onionaddr, new_line)
      .expect("Writing header failed");
  write!(&mut header, "{}\"sattestor_labels\":\"{}\",{}", indentation, sattestor_labels, new_line)
      .expect("Writing header failed");
  header
}

fn construct_pretty_sat_object(hostname: &str, onionaddr: &str, sattestations: &str, sattestor_labels: &str) -> String {
  const BRACE_INDENTATION: [u8; 6] = [0x20; 6];
  const CONTENT_INDENTATION: [u8; 8] = [0x20; 8];
  let brace_indent: String = String::from_utf8(BRACE_INDENTATION.to_vec()).unwrap();
  let content_indent: String = String::from_utf8(CONTENT_INDENTATION.to_vec()).unwrap();
  let mut sat_list: Vec<String> = Vec::new();

  //sattestations.split(":").map(|&s| s.split(",").map(|&v| sat.push_str(&v)).collect()).collect();
  for s in sattestations.split(";") {
    let sattestee: Vec<&str> = s.split(":").collect();
    if sattestee.len() != 5 {
      continue;
    }
    let mut sat = String::new();
    sat.push_str(&format!("{}{{\n", brace_indent));
    sat.push_str(&print_sat_token_content(&content_indent, &sattestee));
    //sat.push_str(&format!("{}  \"sattestee\":   \"{}\",\n", sat_indent, sattestee[0]));
    //sat.push_str(&format!("{}  \"onion\":       \"{}\",\n", sat_indent, sattestee[1]));
    //sat.push_str(&format!("{}  \"labels\":      \"{{{}}}\",\n", sat_indent, sattestee[2]));
    //sat.push_str(&format!("{}  \"valid_after\": \"{}\"\n", sat_indent, sattestee[3]));
    sat.push_str(&format!("{}}}", brace_indent));
    sat_list.push(sat);
  }
  let mut sat = String::from("[\n");
  sat.push_str(&sat_list.join(",\n"));
  sat.push_str("\n    ]");

  // "sattestor" is the traditional domain name of the sattestor
  // "onion" is the self-authenticating name of the sattestor.
  //   It must be a public key. It must validate the signature
  //   over this sattestation
  // "sattestees" is a list of sattestations.
//  format!(
//" {{
//    \"sattestor\":   \"{}\",
//    \"onion\":       \"{}\",
//    \"label\":       \"{{*}}\",
//    \"sattestees\": {}
//  }}",
//    hostname, onionaddr, sat).to_string()

  let r = format!(
" {{
{}    \"sattestees\": {}
  }}",
  construct_sat_token_header(hostname, onionaddr, sattestor_labels, "    ", "\n"),
  sat).to_string();
  r
}

fn make_sat_list(expanded_sec_key: &ExpandedSecretKey, public_key: &PublicKey, hostname: &str, onionaddr: &str, sattestations: &str, sattestor_labels: &str) -> String {
    let msg = construct_pretty_sat_object(&hostname, &onionaddr, &sattestations, sattestor_labels);
    let tagged_msg = format!("{}{}", "sattestation-list-v0", msg);
    let sig = expanded_sec_key.sign(tagged_msg.as_bytes(), &public_key).to_bytes();

    assert!(public_key.verify(tagged_msg.as_bytes(), &Signature::from_bytes(&sig).unwrap()).is_ok());

    let b64 = base64::encode(&sig as &[u8]);

    format!("{{\n  \"sattestation\": {},\n  \"signature\": \"{}\"\n}}", msg, b64)
}

fn make_sat_tokens(expanded_sec_key: &ExpandedSecretKey, public_key: &PublicKey, hostname: &str, onionaddr: &str, sattestations: &str, sattestor_labels: &str) -> Vec<String> {
  let mut tokens = Vec::new();
  for s in sattestations.split(";") {
    let sattestee: Vec<&str> = s.split(":").collect();
    if sattestee.len() != 5 {
      continue;
    }
    let mut unsigned_token = String::new();
    let mut signed_token = String::new();
    let header = construct_sat_token_header(hostname, onionaddr, sattestor_labels, "", "");
    let token = construct_sat_token(&sattestee).unwrap();
    write!(unsigned_token, "{{{}{}}}", header, token).expect("Writing unsigned token failed");

    let tagged_token = format!("{}{}", "sattestation-token-v0", unsigned_token);
    let sig = expanded_sec_key.sign(tagged_token.as_bytes(), &public_key).to_bytes();

    assert!(public_key.verify(tagged_token.as_bytes(), &Signature::from_bytes(&sig).unwrap()).is_ok());

    let b64_sig = base64::encode(&sig as &[u8]);

    write!(signed_token, "{{sattestation:{},signature:{}}}", unsigned_token, b64_sig).expect("Writing signed token failed");
    let b64_token = base64::encode(&signed_token.as_bytes());
    tokens.push(b64_token);
  }
  tokens
}


fn make_satis_sig_v1(expanded_sec_key: &ExpandedSecretKey, public_key: &PublicKey,
                hostname: &str, onionaddr: &str, fingerprint: &str, time: u64,
                validity_width: u64, nonce: u32, labels: &str) -> String {
    // Format:
    //  magic string
    //  64bit time of middle of validity window (seconds since 1970)
    //  64bit width of validity window (seconds)
    //  32bit nonce
    //  32bit domain str length
    //  varied domain str
    //  32bit fingerprint str length
    //  varied fingerprint str
    //  32bit labels str length
    //  varied labels str
    //
    const MAGIC: &'static str = "satis-guard-v1-----";
    const SIZE_OF_U64: usize = std::mem::size_of::<u64>();
    const SIZE_OF_U32: usize = std::mem::size_of::<u32>();
    let sata = format!("{}onion.{}", onionaddr, hostname);
    let msg_len: usize = MAGIC.len() + SIZE_OF_U64 + SIZE_OF_U64 + SIZE_OF_U32 + SIZE_OF_U32 + sata.len() + SIZE_OF_U32 + fingerprint.len() + SIZE_OF_U32 + labels.len();
    let mut satis_msg = Vec::new();
    satis_msg.resize(msg_len, 0);
    let satis_msg: &mut [u8] = satis_msg.as_mut_slice();
    
    let (msg_magic, buf) = satis_msg.split_at_mut(MAGIC.len());
    let (msg_window, buf) = buf.split_at_mut(SIZE_OF_U64);
    let (msg_validity, buf) = buf.split_at_mut(SIZE_OF_U64);
    let (msg_nonce, buf) = buf.split_at_mut(SIZE_OF_U32);
    let (msg_hostname_len, buf) = buf.split_at_mut(SIZE_OF_U32);
    let (msg_hostname, buf) = buf.split_at_mut(sata.len());
    let (msg_fingerprint_len, buf) = buf.split_at_mut(SIZE_OF_U32);
    let (msg_fingerprint , buf) = buf.split_at_mut(fingerprint.len());
    let (msg_labels_len, buf) = buf.split_at_mut(SIZE_OF_U32);
    let msg_labels = buf;

    assert_eq!(msg_labels.len(), labels.len());

    msg_magic.copy_from_slice(&MAGIC.as_bytes());
    msg_window.copy_from_slice(&time.to_be_bytes());
    msg_validity.copy_from_slice(&validity_width.to_be_bytes());
    msg_nonce.copy_from_slice(&nonce.to_be_bytes());
    msg_hostname_len.copy_from_slice(&(sata.len() as u32).to_be_bytes());
    msg_hostname.copy_from_slice(sata.as_bytes());
    msg_fingerprint_len.copy_from_slice(&(fingerprint.len() as u32).to_be_bytes());
    msg_fingerprint.copy_from_slice(fingerprint.as_bytes());
    msg_labels_len.copy_from_slice(&(labels.len() as u32).to_be_bytes());
    msg_labels.copy_from_slice(labels.as_bytes());

    //let satis_msg = format!("{}{}{}{}{}{}{}{}",
    //                        magic, time, validity_width, nonce, hostname.len(),
    //                        hostname, fingerprint.len(), fingerprint);

    let sig = expanded_sec_key.sign(&satis_msg, &public_key).to_bytes();

    assert!(public_key.verify(satis_msg, &Signature::from_bytes(&sig).unwrap()).is_ok());

    let mut signed_msg = Vec::new();
    signed_msg.extend_from_slice(satis_msg);
    signed_msg.extend_from_slice(&sig);

    let b64 = base64::encode(signed_msg.as_slice());

    String::from(b64)
}

fn make_satis_sig(expanded_sec_key: &ExpandedSecretKey, public_key: &PublicKey,
                hostname: &str, onionaddr: &str, fingerprint: &str, time: u64,
                validity_width: u64, nonce: u32) {
    // Format:
    //  magic string
    //  64bit time of middle of validity window (seconds since 1970)
    //  64bit width of validity window (seconds)
    //  32bit nonce
    //  32bit domain str length
    //  varied domain str
    //  32bit fingerprint str length
    //  varied fingerprint str
    //
    const MAGIC: &'static str = "satis-guard-----";
    const SIZE_OF_U64: usize = std::mem::size_of::<u64>();
    const SIZE_OF_U32: usize = std::mem::size_of::<u32>();
    let sata = format!("{}onion.{}", onionaddr, hostname);
    let msg_len: usize = MAGIC.len() + SIZE_OF_U64 + SIZE_OF_U64 + SIZE_OF_U32 + SIZE_OF_U32 + sata.len() + SIZE_OF_U32 + fingerprint.len();
    let mut satis_msg = Vec::new();
    satis_msg.resize(msg_len, 0);
    let satis_msg: &mut [u8] = satis_msg.as_mut_slice();
    
    let (msg_magic, buf) = satis_msg.split_at_mut(MAGIC.len());
    let (msg_window, buf) = buf.split_at_mut(SIZE_OF_U64);
    let (msg_validity, buf) = buf.split_at_mut(SIZE_OF_U64);
    let (msg_nonce, buf) = buf.split_at_mut(SIZE_OF_U32);
    let (msg_hostname_len, buf) = buf.split_at_mut(SIZE_OF_U32);
    let (msg_hostname, buf) = buf.split_at_mut(sata.len());
    let (msg_fingerprint_len, buf) = buf.split_at_mut(SIZE_OF_U32);
    let msg_fingerprint = buf;

    assert_eq!(msg_fingerprint.len(), fingerprint.len());

    msg_magic.copy_from_slice(&MAGIC.as_bytes());
    msg_window.copy_from_slice(&time.to_be_bytes());
    msg_validity.copy_from_slice(&validity_width.to_be_bytes());
    msg_nonce.copy_from_slice(&nonce.to_be_bytes());
    msg_hostname_len.copy_from_slice(&(sata.len() as u32).to_be_bytes());
    msg_hostname.copy_from_slice(sata.as_bytes());
    msg_fingerprint_len.copy_from_slice(&(fingerprint.len() as u32).to_be_bytes());
    msg_fingerprint.copy_from_slice(fingerprint.as_bytes());

    //let satis_msg = format!("{}{}{}{}{}{}{}{}",
    //                        magic, time, validity_width, nonce, hostname.len(),
    //                        hostname, fingerprint.len(), fingerprint);

    let sig = expanded_sec_key.sign(&satis_msg, &public_key).to_bytes();

    assert!(public_key.verify(satis_msg, &Signature::from_bytes(&sig).unwrap()).is_ok());

    let mut signed_msg = Vec::new();
    signed_msg.extend_from_slice(satis_msg);
    signed_msg.extend_from_slice(&sig);

    let b64 = base64::encode(signed_msg.as_slice());

    println!("{}\n", b64);
    println!("Using nonce: {}\n", nonce);
}

fn write_file(outdir: &str, path: &str, sig: &str) {
    let fullpath = format!("{}{}", &outdir, path);
    let path = Path::new(&fullpath);
    let display = path.display();

    // Open a file in write-only mode, returns `io::Result<File>`
    let mut file = match File::create(&path) {
        Err(why) => panic!("couldn't create {}: {}", display, why.to_string()),
        Ok(file) => file,
    };

    // Write the `LOREM_IPSUM` string to `file`, returns `io::Result<()>`
    match file.write_all(sig.as_bytes()) {
        Err(why) => panic!("couldn't write to {}: {}", display, why.to_string()),
        Ok(_) => println!("successfully wrote to {}", display),
    }
}

fn now() -> u64 {
  let sys_time = SystemTime::now();
  sys_time.duration_since(SystemTime::UNIX_EPOCH)
          .expect("Could not retrieve current time")
          .as_secs()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 9 {
        println!("Provide: <path to keys> <hostname> <onion address> <fingerprint> <self-labels> <sattestor labels> <in (config) directory> <out directory>");
        return;
    }
    let path = args[1].clone();
    let hostname = args[2].clone();
    let onionaddr = args[3].clone();
    let fingerprint = args[4].clone();
    let self_labels = args[5].clone();
    let sattestor_labels = args[6].clone();
    let indir = args[7].clone();
    let outdir = args[8].clone();
    let secret_key_file_path = format!("{}{}{}", path, KEY_FILE_PREFIX, SECRET_KEY_FILE_SUFFIX);
    let public_key_file_path = format!("{}{}{}", path, KEY_FILE_PREFIX, PUBLIC_KEY_FILE_SUFFIX);
    let sattestation_file_path = format!("{}{}", indir, SATTESTATION_CSV);

    let raw_public_key = match read_to_string(public_key_file_path.clone()) {
        Ok(s) => Vec::from(s.as_bytes()),
        Err(e) => {
            //println!("Error reading file: {}: {:?}", public_key_file_path, e);
            if e.kind() != ErrorKind::InvalidData {
                return;
            }
 
            let mut pk_file: File = match open_key_file(public_key_file_path.clone()) {
                Ok(v) => v,
                Err(e) => {
                    println!("Error opening file: {}: {:?}", public_key_file_path, e);
                    return;
                },
            };
            let mut raw_public_key = Vec::new();
            let raw_public_key_len = match read_from_file(&mut pk_file, &mut raw_public_key) {
                Ok(s) => s,
                Err(e) => {
                    println!("Error reading public key file: {}: {:?}", public_key_file_path, e);
                    return;
                },
            };
            if raw_public_key_len == 0 {
                println!("Read from file but it is empty: {}", public_key_file_path);
            }
            raw_public_key
        }
    };

    let raw_secret_key = match read_key(&secret_key_file_path.clone()) {
        Ok(s) => s,
        Err(e) => {
            println!("Error reading file: {}: {:?}", secret_key_file_path, e);
            return;
        },
    };

    let seckey = match parse_secret_key(&raw_secret_key) {
        Ok(v) => v,
        Err(r) => {
            println!("Error while parsing secret key: {:?}", r);
            return;
        }
    };

    let pubkey = match parse_tagged_key("ed25519v1-public", "type0", &raw_public_key, 32) {
        Ok(v) => v,
        Err(r) => {
            println!("Error while parsing public key: {:?}", r);
            return;
        }
    };

    let expanded_sec_key = match ExpandedSecretKey::from_bytes(&seckey[..]) {
        Ok(k) => k,
        Err(r) => {
            println!("Expanded Secret Key was not valid: {:?}", r);
            return;
        }
    };

    let public_key = match PublicKey::from_bytes(&pubkey[..]) {
        Ok(k) => k,
        Err(r) => {
            println!("Public Key was not valid: {:?}", r);
            return;
        }
    };

    let mut is_sattestor = false;
    let sattestations = match read_sattestation(&sattestation_file_path.clone()) {
        Ok(s) => {
            is_sattestor = true;
            s
        },
        Err(e) => {
            println!("Error reading file: {}: {:?}", sattestation_file_path, e);
            "".to_string()
        },
    };

    let now: u64 = now();
    const SEVEN_DAY_VALIDITY_PERIOD: u64 = 60*60*24*7;
    let nonce: u32 = rand::thread_rng().next_u32();
    let good_sig = make_satis_sig_v1(&expanded_sec_key, &public_key, &hostname, &onionaddr, &fingerprint, now, SEVEN_DAY_VALIDITY_PERIOD, nonce, &self_labels);

    const BAD_FINGERPRINT: &'static str = "DEADBEEF111111111111";
    let bad_fingerprint = make_satis_sig_v1(&expanded_sec_key, &public_key, &hostname, &onionaddr, BAD_FINGERPRINT, now, SEVEN_DAY_VALIDITY_PERIOD, nonce, &self_labels);

    const BAD_TIME_CENTER: u64 = 9;
    let bad_time = make_satis_sig_v1(&expanded_sec_key, &public_key, &hostname, &onionaddr, &fingerprint, BAD_TIME_CENTER, SEVEN_DAY_VALIDITY_PERIOD, nonce, &self_labels);

    const BAD_DOMAIN: &'static str = "example.com";
    let bad_domain = make_satis_sig_v1(&expanded_sec_key, &public_key, &BAD_DOMAIN, &onionaddr, &fingerprint, now, SEVEN_DAY_VALIDITY_PERIOD, nonce, &self_labels);

    let mut bad_sig = good_sig.clone();
    let middle = bad_sig.len()/2;
    let c = bad_sig.remove(middle);
    bad_sig.insert(middle-1, c);

    const BAD_LABEL: &'static str = "foo";
    let bad_label = make_satis_sig_v1(&expanded_sec_key, &public_key, &hostname, &onionaddr, &fingerprint, now, SEVEN_DAY_VALIDITY_PERIOD, nonce, BAD_LABEL);

    write_file(&outdir, "satis_sig", &good_sig);
    write_file(&outdir, "satis_sig_bad_time", &bad_time);
    write_file(&outdir, "satis_sig_bad_fp", &bad_fingerprint);
    write_file(&outdir, "satis_sig_bad_domain", &bad_domain);
    write_file(&outdir, "satis_sig_bad_sig", &bad_sig);
    write_file(&outdir, "satis_sig_bad_label", &bad_label);

    if !is_sattestor {
        return;
    }

    let sattestations = sattestations.replace("\n",";");

    let satlist = make_sat_list(&expanded_sec_key, &public_key, &hostname, &onionaddr, &sattestations, &sattestor_labels);
    write_file(&outdir, "sattestation.json", &satlist);
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_serde() {
      let hostname = "sata.example.org";
      let onionaddr = "l4yxbgn74e6ukw6zv3jojaf6bkqlgea2ny37ocry2i4xartdjkqqxwid";
      let sattestations = String::from("domain=satis.system33.pw:onion=hllvtjcjomneltczwespyle2ihuaq5hypqaavn3is6a7t2dojuaa6ryd:labels=news:valid_after=2020-04-30:refreshed_on=2020-05-15");
      let secret_key = "PT0gZWQyNTUxOXYxLXNlY3JldDogdHlwZTAgPT0AAAC4pxnkg/1N6OIt/KdRPJPvvXcyNBvRzMlBGb7rjZ0GZ0qVldDtwQFJ13OMkPAPORHbeSsY5izrIFyRVye/ifoI";
      let public_key = "PT0gZWQyNTUxOXYxLXB1YmxpYzogdHlwZTAgPT0AAABfMXCZv+E9RVvZrtLkgL4KoLMQGm439wo40jlwRmNKoQ==";

      let sattestee: Vec<&str> = sattestations.split(":").collect();

      let sat_token_content = print_sat_token_content(" ", &sattestee);
      let expected_token_content = " \"domain\": \"satis.system33.pw\",
 \"onion\": \"hllvtjcjomneltczwespyle2ihuaq5hypqaavn3is6a7t2dojuaa6ryd\",
 \"labels\": \"news\",
 \"valid_after\": \"2020-04-30\",
 \"refreshed_on\": \"2020-05-15\"\n";
      assert_eq!(expected_token_content, sat_token_content);

      let sat_token_header = construct_sat_token_header(hostname, onionaddr, "*", " ", "\n");
      let expected_token_header = " \"sat_list_version\":\"1\",
 \"sattestor_domain\":\"sata.example.org\",
 \"sattestor_onion\":\"l4yxbgn74e6ukw6zv3jojaf6bkqlgea2ny37ocry2i4xartdjkqqxwid\",
 \"sattestor_labels\":\"*\",\n";
      assert_eq!(expected_token_header, sat_token_header);

      let msg = construct_pretty_sat_object(&hostname, &onionaddr, &sattestations, "*");
      let expected_sat_object = format!(" {{
    \"sat_list_version\":\"1\",
    \"sattestor_domain\":\"{}\",
    \"sattestor_onion\":\"{}\",
    \"sattestor_labels\":\"*\",
    \"sattestees\": [
      {{
        \"domain\": \"satis.system33.pw\",
        \"onion\": \"hllvtjcjomneltczwespyle2ihuaq5hypqaavn3is6a7t2dojuaa6ryd\",
        \"labels\": \"news\",
        \"valid_after\": \"2020-04-30\",
        \"refreshed_on\": \"2020-05-15\"
      }}
    ]
  }}", hostname, onionaddr);
      assert_eq!(expected_sat_object, msg);

      let sat_token = construct_sat_token(&sattestee).unwrap();
      let expected_token = "\"domain\":\"satis.system33.pw\",\"onion\":\"hllvtjcjomneltczwespyle2ihuaq5hypqaavn3is6a7t2dojuaa6ryd\",\"labels\":\"news\",\"valid_after\":\"2020-04-30\",\"refreshed_on\":\"2020-05-15\"";
      assert_eq!(expected_token, sat_token);

      let raw_secret_key = base64::decode(secret_key.as_bytes()).unwrap();
      let raw_public_key = base64::decode(public_key.as_bytes()).unwrap();

      // 32-byte header, 64-byte key
      assert_eq!(raw_secret_key.len(), 96);
      // 32-byte header, 32-byte key
      assert_eq!(raw_public_key.len(), 64);

      let seckey = match parse_tagged_key("ed25519v1-secret", "type0", &raw_secret_key, 64) {
          Ok(v) => v,
          Err(r) => {
              assert!(false, "Error while parsing public key: {:?}", r);
              return;
          }
      };

      let pubkey = match parse_tagged_key("ed25519v1-public", "type0", &raw_public_key, 32) {
          Ok(v) => v,
          Err(r) => {
              assert!(false, "Error while parsing public key: {:?}", r);
              return;
          }
      };

      assert_eq!(seckey.len(), 64);
      assert_eq!(pubkey.len(), 32);

      let expanded_sec_key = match ExpandedSecretKey::from_bytes(&seckey) {
          Ok(k) => k,
          Err(r) => {
              assert!(false, "Expanded Secret Key was not valid: {:?}", r);
              return;
          }
      };

      let public_key = match PublicKey::from_bytes(&pubkey) {
          Ok(k) => k,
          Err(r) => {
              assert!(false, "Public Key was not valid: {:?}", r);
              return;
          }
      };

      let sat_tokens = make_sat_tokens(&expanded_sec_key, &public_key, hostname, onionaddr, &sattestations, "*");

      assert!(sat_tokens.len() > 0);
        
      let expected_unsigned_sat_tokens = "{\"sat_list_version\":\"1\",\"sattestor_domain\":\"sata.example.org\",\"sattestor_onion\":\"l4yxbgn74e6ukw6zv3jojaf6bkqlgea2ny37ocry2i4xartdjkqqxwid\",\"sattestor_labels\":\"*\",\"domain\":\"satis.system33.pw\",\"onion\":\"hllvtjcjomneltczwespyle2ihuaq5hypqaavn3is6a7t2dojuaa6ryd\",\"labels\":\"news\",\"valid_after\":\"2020-04-30\",\"refreshed_on\":\"2020-05-15\"}";

      let expected_tagged_token = format!("{}{}", "sattestation-token-v0", expected_unsigned_sat_tokens);
      let expected_sig = expanded_sec_key.sign(expected_tagged_token.as_bytes(), &public_key).to_bytes();

      assert!(public_key.verify(expected_tagged_token.as_bytes(), &Signature::from_bytes(&expected_sig).unwrap()).is_ok());

      let b64_sig = base64::encode(&expected_sig[..]);
      let expected_signed_token = format!("{{sattestation:{},signature:{}}}", expected_unsigned_sat_tokens, b64_sig);
      let expected_b64_token = base64::encode(&expected_signed_token);


      let expected_decoded_token = base64::decode(expected_b64_token.clone()).unwrap();
      let decoded_token = base64::decode(sat_tokens[0].clone()).unwrap();
      assert_eq!(String::from_utf8(expected_decoded_token).unwrap(), String::from_utf8(decoded_token).unwrap());

      assert_eq!(expected_b64_token, sat_tokens[0].clone());
    }
}

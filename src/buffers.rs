use crate::networking::verify_ip;
use sha2::{Sha256, Digest};
use rand::{rngs::OsRng, RngCore};
use aes_gcm::{aead::{heapless::Vec, Aead, NewAead}, Aes256Gcm, Key, Nonce as OtherNonce};

pub const BUFFER_SIZE: usize = 1280;
pub const LEN_BYTES: usize = 4;
pub const IV_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
pub const CIPHER_WITH_TAG: usize = BUFFER_SIZE + TAG_SIZE;
pub const SERIALIZED_SIZE: usize = CIPHER_WITH_TAG + IV_SIZE + LEN_BYTES + 1;


pub struct RxBuffer {
    pub encrypted: bool,
    pub address: [u8; 4],
    pub port: u16,
    pub message_buffer: [u8; CIPHER_WITH_TAG],
    pub len: u32,
    pub iv: [u8; IV_SIZE],
}

pub struct TxBuffer {
    pub encrypted: bool,
    pub address: [u8; 4],
    pub port: u16,
    pub string_address: String,
    pub message_buffer: [u8; CIPHER_WITH_TAG],
    pub len: u32,
    pub iv: [u8; IV_SIZE],
}

impl RxBuffer {

    pub fn decrypt(&mut self, key: &str) {
        if self.encrypted == true {
            let key: [u8; 32] = derive_key(key);

            let cipher = Aes256Gcm::new(Key::from_slice(&key));

            let nonce: &aead::generic_array::GenericArray<u8, _> = OtherNonce::from_slice(&self.iv);

            let ciphertext_vec: Vec<u8, CIPHER_WITH_TAG> = Vec::from_slice(&self.message_buffer).unwrap();
            let cipher_slice: &[u8] = &ciphertext_vec;

            match cipher.decrypt(nonce, cipher_slice) {
                Ok(plain_text) => {
                    self.message_buffer[..1280].copy_from_slice(&plain_text);
                    self.encrypted = false;
                    println!("Successfully Decrypted Incoming Message\n");
                }
                Err(_) => {
                    eprintln!("Decryption failed");
                }
            }
        } else {
            println!("Buffer already plain text");
        }

    }

    pub fn print_message(&self) {

        if self.encrypted == false {
            let msg: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&self.message_buffer[..self.len as usize]);
            println!("From: {}.{}.{}.{}:{}\n",&self.address[0],&self.address[1],&self.address[2],&self.address[3],&self.port);
            println!("Message:\n{}", msg);
        } else {
            println!("Cannot print encrypted message!");
        }
    }

}


impl TxBuffer {

    pub fn encrypt(&mut self, key: &str) {

        if self.encrypted == false {
            let key: [u8; 32] = derive_key(key);

            let cipher = Aes256Gcm::new(Key::from_slice(&key));

            OsRng.fill_bytes(&mut self.iv);
            let nonce: &aead::generic_array::GenericArray<u8, _> = OtherNonce::from_slice(&self.iv);

            let plain_text: Vec<u8, BUFFER_SIZE> = Vec::from_slice(&self.message_buffer[..BUFFER_SIZE]).unwrap();
            let message_slice: &[u8] = &plain_text;

            match cipher.encrypt(nonce, message_slice) {
                Ok(ciphertext) => {
                    self.message_buffer.copy_from_slice(&ciphertext);
                    self.encrypted = true;
                    println!("Successfully Encrypted Outgoing Message\n");
                }
                Err(_) => {
                    eprintln!("Encryption failed");
                }
            }
        } else {
            println!("Buffer already encrypted");
        }
    }

    pub fn decrypt(&mut self, key: &str) {

        if self.encrypted == true {
            let key: [u8; 32] = derive_key(key);

            let cipher = Aes256Gcm::new(Key::from_slice(&key));

            let nonce: &aead::generic_array::GenericArray<u8, _> = OtherNonce::from_slice(&self.iv);

            let ciphertext_vec: Vec<u8, CIPHER_WITH_TAG> = Vec::from_slice(&self.message_buffer).unwrap();
            let cipher_slice: &[u8] = &ciphertext_vec;

            match cipher.decrypt(nonce, cipher_slice) {
                Ok(plain_text) => {
                    self.message_buffer[..1280].copy_from_slice(&plain_text);
                    self.encrypted = false;
                    println!("Successfully Decrypted Outgoing Message\n");
                }
                Err(_) => {
                    eprintln!("Decryption failed");
                }
            }
        } else {
            println!("Buffer already plain text");
        }
    }

    pub fn clear(&mut self) {
            self.message_buffer = [0u8; CIPHER_WITH_TAG];
            self.encrypted = false;
            self.len = 0;
            println!("Successfully Cleared Outgoing Message Buffer\n");
    }

    pub fn print_message(&self) {
        if self.encrypted == false {
            let msg: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&self.message_buffer[..self.len as usize]);
            println!("Current Message:\n{}",msg);
        } else {
            println!("Cannot print encrypted message");
        }
    }

    pub fn message(&mut self, msg: &str) {

        self.clear();

        let bytes = msg.as_bytes();

        if BUFFER_SIZE >= bytes.len() {

            self.len = bytes.len() as u32;
            println!("Successfuly Wrote Message Metadata\n");

            self.message_buffer[..bytes.len()].copy_from_slice(bytes);
            println!("Successfully Wrote Message to Outbound Buffer.\n");

        } else {
            println!("Message too long. (1280 Characters Max)\n")
        }

    }

    pub fn update_address(&mut self, addy: &str) {
        match verify_ip(addy) {
            true => self.string_address = addy.to_string(),
            false => println!("Not a valid IP")
        }
    }

    pub fn serialize(&self) -> [u8; SERIALIZED_SIZE] {
        let mut send_buf = [0u8; SERIALIZED_SIZE];
        let size = self.len;
    
        send_buf[0] = if self.encrypted { 1 } else { 0 };
        send_buf[1..5].copy_from_slice(&size.to_le_bytes());
        send_buf[5..17].copy_from_slice(&self.iv);
        send_buf[17..].copy_from_slice(&self.message_buffer);

        println!("Successfully Serialized Outgoing Buffer\n");

        return send_buf
    }


}

pub fn deserialize(rx_buf: &mut RxBuffer, buf: [u8; SERIALIZED_SIZE]) {
    
    if buf[0] == 1 {
        rx_buf.encrypted = true;
    } else {
        rx_buf.encrypted = false;
    }

    rx_buf.len = u32::from_le_bytes(buf[1..5].try_into().unwrap());
    rx_buf.iv = buf[5..17].try_into().unwrap();
    rx_buf.message_buffer = buf[17..].try_into().unwrap();
    println!("Successfully Deserialized Incoming Message\n");

}

fn derive_key(key: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    let hash = hasher.finalize();

    let mut key = [0u8; 32];
    key.copy_from_slice(&hash[..32]);

    return key
}
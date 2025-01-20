use std::fmt::Error;
use std::net::{SocketAddrV4, UdpSocket};
use std::time::Duration;
use rand::Rng;

use crate::buffers::TxBuffer;

fn generate_transaction_id() -> [u8; 12] {

    let mut rng = rand::thread_rng();
    let mut transaction_id = [0u8; 12];
    rng.fill(&mut transaction_id);
    
    transaction_id

}

fn print_address(socket: &UdpSocket) -> std::io::Result<()> {

    let stun_server = "stun.l.google.com:19302";

    match socket.local_addr() {
        Ok(addr) => println!("Local address: {}",addr),
        Err(e) => println!("Failed to get local address: {}", e),
    }
    let trans_id = generate_transaction_id();
    let mut req = vec![0x00, 0x01];
    req.extend_from_slice(&[0x00, 0x00]);
    req.extend_from_slice(b"R\0*\x12");
    req.extend_from_slice(&trans_id);

    socket.send_to(&req, stun_server).expect("Error Contacting Google STUN");

    let mut buf = [0u8; 512];
    match socket.recv_from(&mut buf) {
        Ok((size, _)) => {
            if size >= 20 {

                if &buf[8..20] == trans_id {
                    println!("ID OK");
                } else {
                    print!("TRANSACTION ID MISMATCH\nINFORMATION MAY BE UNRELIABLE");
                }

                if &buf[4..8] == b"R\0*\x12" {
                    println!("Recieved valid STUN response");

                    let mut idx = 20;
                    while idx + 4 < size {
                        let attr_type = u16::from_be_bytes([buf[idx], buf[idx + 1]]);
                        let attr_length = u16::from_be_bytes([buf[idx + 2],buf[idx + 3]]) as usize;

                        println!("Attr Type: {:#06x}, Len: {}", attr_type ,attr_length);

                        if idx + 4 + attr_length > size {
                            println!("Malformed STUN attribute Length");
                        }

                        if attr_type == 0x0001 && attr_length >= 8 {
                            let family = buf[idx + 5];
                            println!("Family: {:#04x}", family);
                            if family == 0x01 {
                                let port = u16::from_be_bytes([buf[idx + 6], buf[idx + 7]]);
                                let ip = [
                                    buf[idx + 8],
                                    buf[idx + 9],
                                    buf[idx + 10],
                                    buf[idx + 11]
                                ];
                                println!("Public Address {}.{}.{}.{}:{} \n(Mapped Address)\n",ip[0],ip[1],ip[2],ip[3],port);
                                break
                            } else {
                                println!("Address is not mapped, attempting to extract XOR Mapped Address.\n")
                            }
                        }

                        if attr_type == 0x0020 && attr_length >= 8 {
                            let family = buf[idx + 5];
                            if family == 0x01 {
                                let x_port = u16::from_be_bytes([buf[idx + 6], buf[idx + 7]]) ^ 0x2112;
                                let x_ip = [
                                    buf[idx + 8] ^ 0x21,
                                    buf[idx + 9] ^ 0x12,
                                    buf[idx + 10] ^ 0xA4,
                                    buf[idx + 11] ^ 0x42
                                ];
                                println!("Public Address: {}.{}.{}.{}:{} \n(XOR Mapped Address)\n",x_ip[0], x_ip[1], x_ip[2], x_ip[3], x_port);
                            }
                            break
                        } else {
                            println!("Unsupported XOR Masking");
                        }
                        idx += 4 + attr_length;
                        idx = (idx + 3) & !3;
                    }
                } else {
                    println!("Invalid STUN response: Magic Cookie mismatch");
                }
            }
        }
        
        Err(e) => {println!("Failed to recieve STUN response: {:?}",e);}

    }

    Ok(())
}

pub fn create_sockets() -> Result<(UdpSocket,UdpSocket), Error> {

    let tx_socket = UdpSocket::bind("0.0.0.0:0").expect("Binding operation failed (tx).");
    tx_socket.set_read_timeout(Some(Duration::from_secs(5))).expect("Read Timeout Error (tx).");

    let rx_socket = UdpSocket::bind("0.0.0.0:0").expect("Binding operation failed (rx).");
    rx_socket.set_read_timeout(Some(Duration::from_secs(5))).expect("Read Timeout Error (rx).");

    println!("TX SOCKET: ");
    print_address(&tx_socket).expect("Error printing tx socket addresses");

    println!("RX SOCKET: ");
    print_address(&rx_socket).expect("Error printing rx socket");



    Ok((tx_socket,rx_socket))

}

pub fn send(queue: &TxBuffer, socket: &UdpSocket) {

    let send_buf = queue.serialize();
    socket.send_to(&send_buf, &queue.string_address).expect("Unable to send message.");
    println!("Message Send Success");

}

pub fn verify_ip(address: &str) -> bool {
    match address.parse::<SocketAddrV4>() {
        Ok(_) => true,
        Err(_) => false
    }
}
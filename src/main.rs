use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use buffers::{deserialize, RxBuffer, TxBuffer, SERIALIZED_SIZE};

mod buffers;
mod networking;

const COMMAND_IND: usize = 5;
const DATA_IND: usize = 6;
const MAX_INPUT_LENGTH: usize = 1286;

fn main() -> std::io::Result<()> {

    println!("Welcome!\nThe RX Address is the address to receive messages\nThe TX address is the address you are sending from.\n");
    println!("AES-256 keys and addresses are exchanged outside of this program.\n\n");
    help();

    let (tx_socket, rx_socket) = networking::create_sockets().expect("Failed to assign sockets");


    //let (_recv_tx, _recv_rx) = mpsc::channel::<Comms>();
    let (process_tx, process_rx) = mpsc::channel::<Comms>();
    let (send_tx, send_rx) = mpsc::channel::<Comms>();
    let (_input_tx, _input_rx) = mpsc::channel::<Comms>();


    //spawn rec thread
    let process_tx_rec = process_tx.clone();
    thread::spawn(move|| {
        let rec_socket = rx_socket.try_clone().expect("Unable to clone RX socket");
        rec_socket.set_nonblocking(true).expect("couldnt set non-blocking");
        let mut buf: [u8; buffers::SERIALIZED_SIZE] = [0; buffers::SERIALIZED_SIZE];
        loop {
            match rec_socket.recv_from(&mut buf) {
                Ok((mesg, src_addy)) => {
                    if mesg == SERIALIZED_SIZE {
                        match src_addy {
                            SocketAddr::V4(v4_addr) => {
                                let mut rx: RxBuffer = RxBuffer{
                                    encrypted: false,
                                    address: [0u8 ;4],
                                    port: 0,
                                    message_buffer: [0u8; buffers::CIPHER_WITH_TAG],
                                    len: 0,
                                    iv: [0u8; buffers::IV_SIZE]
                                };
                                rx.address = v4_addr.ip().octets();
                                rx.port = v4_addr.port();
                                println!("Receiveced Message From: {}.{}.{}.{}:{}",&rx.address[0],&rx.address[1],&rx.address[2],&rx.address[3],&rx.port);
                                deserialize(&mut rx, buf);
                                process_tx_rec.send(Comms::Buffer(rx)).expect("thread send failure");
                            },
                            SocketAddr::V6(v6_addr) => println!("IPV6 Detected {:?}, some features are not available.",
                                            v6_addr.ip().octets())                            
                        }
                    } else {
                        println!("Malformed Packet, No operations available");
                    }
                },
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Sleep for a short duration before retrying
                    thread::sleep(Duration::from_millis(10));
                },
                Err(e) => eprintln!("Error: {} receiving message",e)
            }
        }
    });

    //spawn message process thread
    thread::spawn(move || {
        let mut rx: RxBuffer = RxBuffer{
            encrypted: false,
            address: [0u8 ;4],
            port: 0,
            message_buffer: [0u8; buffers::CIPHER_WITH_TAG],
            len: 0,
            iv: [0u8; buffers::IV_SIZE]
        };
        loop {
            match process_rx.recv() {
                Ok(Comms::Buffer(data)) => {rx = data;
                    println!("Incoming Message Ready for Operations\n");
                },
                Ok(Comms::Command(data)) => match &data[..COMMAND_IND] {
                    "-deci" => if data.len() > 6 {
                        rx.decrypt(&data[DATA_IND..])
                    } else {
                            println!("No valid key");
                        },
                    "-shwi" => rx.print_message(),
                    _ => todo!()

                },
                Err(e) => eprint!("Error on RX processing thread: {}", e)

            }
        }
    });

    //spawn send buffer thread
    thread::spawn( move || {
        let send_socket = tx_socket.try_clone().expect("Unable to clone TX socket");
        let mut tx: TxBuffer = TxBuffer{
            encrypted: false, 
            address: [0u8; 4], 
            port: 0,
            string_address:"0.0.0.0:0".to_string(),
            message_buffer: [0u8; buffers::CIPHER_WITH_TAG],
            len: 0,
            iv: [0u8; buffers::IV_SIZE]
            };
        loop {
            match send_rx.recv() {
                Ok(Comms::Buffer(_data)) => println!("Unexpected payload in send thread"),
                Ok(Comms::Command(data)) => match &data[..COMMAND_IND] {
                    "-msgo" => tx.message(&data[DATA_IND..]),
                    "-show" => tx.print_message(),
                    "-sndo" => networking::send(&tx, &send_socket),
                    "-enco" => if data.len() > DATA_IND {
                        tx.encrypt(&data[DATA_IND..]);
                    } else {
                        println!("No valid key");
                        },
                    "-deco" => if data.len() > DATA_IND {
                        tx.decrypt(&data[DATA_IND..]);
                    } else {
                        println!("No valid key");
                        },
                    "-delo" => tx.clear(),
                    "-addy" => tx.update_address(&data[DATA_IND..]),
                    _ => println!("Invalid command in send thread")
                },
                Err(e) => eprintln!("Error on Send Buffer thread: {}",e)
            }
        }
    });


    //spawn user input thread
    let process_tx_input = process_tx.clone();
    thread::spawn(move || {
        loop {
            //println!("Enter Command:");
            io::stdout().flush().expect("Unable to flush stdout");

            let mut input: String = String::new();
            io::stdin().read_line(&mut input).expect("Something went wrong reading input");

            let input: &str = input.trim();

            if input.len() < 5 {
                println!("Not a valid command");
            } else if input.len() > MAX_INPUT_LENGTH {
                println!("Input overflow, max 1286 characters.")
            } else {

                match &input[..5] {
                    "-help" => help(),
                    "-msgo" => send_tx.send(Comms::Command(input.to_string())).expect("unable to send message"),
                    "-show" => send_tx.send(Comms::Command(input[..5].to_string())).expect("unable to send message"),
                    "-sndo" => send_tx.send(Comms::Command(input[..5].to_string())).expect("unable to send message"),
                    "-enco" => send_tx.send(Comms::Command(input.to_string())).expect("unable to send message"),
                    "-deco" => send_tx.send(Comms::Command(input.to_string())).expect("unable to send message"),
                    "-delo" => send_tx.send(Comms::Command(input[..5].to_string())).expect("unable to send message"),
                    "-addy" => send_tx.send(Comms::Command(input.to_string())).expect("unable to send message"),
                    "-shwi" => process_tx_input.send(Comms::Command(input.to_string())).expect("unable to send message"),
                    "-deci" => process_tx_input.send(Comms::Command(input.to_string())).expect("unable to send message"),
                    _ => println!("Invalid input")

                }
        }
        }
    });

    loop {
        thread::sleep(Duration::from_secs(120));
    }




    Ok(())
}

fn help() {
    println!("Command List:\n");
    println!("-help: Brings up this command reference\n");
    println!("-msgo 'Your Message': Writes 'Your Message' to the message buffer.\n     -Overwrites current buffer.\n");
    println!("-show: Prints current message buffer.\n");
    println!("-sndo: Sends current message buffer to target address\n");
    println!("-enco 'Your Key': Encrypts current message buffer. (AES-256)\n");
    println!("-deco 'Your Key': Decrypts current message buffer.\n");
    println!("-delo: Clears current message buffer.\n");
    println!("-addy 'Recipient's IPV4 address': Writes recipient address to address buffer.\n     Ex. 127.0.0.1:42069\n");
    println!("-shwi: Prints most recent message received.\n");
    println!("-deci 'Your Key': Decrpyts incoming buffer.\n");
}

enum Comms {
    Command(String),
    Buffer(RxBuffer),

}

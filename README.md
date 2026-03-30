# Encrypted UDP Messenger

A command-line peer-to-peer encrypted messaging tool written in Rust. Messages are sent over UDP and can be encrypted with AES-256-GCM.

## Features

- **UDP messaging** — Send and receive messages over UDP sockets
- **AES-256-GCM encryption** — Encrypt/decrypt messages using a passphrase (hashed with SHA-256)
- **STUN support** — Discovers your public IP/port via Google's STUN server on startup
- **Multi-threaded** — Separate threads for receiving, processing, sending, and user input

## Usage

Run the program and use the following commands:

| Command | Description |
|---|---|
| `-help` | Show command reference |
| `-msgo <message>` | Write a message to the outbound buffer |
| `-show` | Print the current outbound message |
| `-enco <key>` | Encrypt the outbound buffer (AES-256-GCM) |
| `-deco <key>` | Decrypt the outbound buffer |
| `-addy <ip:port>` | Set the recipient address (e.g. `127.0.0.1:42069`) |
| `-sndo` | Send the outbound buffer to the target address |
| `-delo` | Clear the outbound buffer |
| `-shwi` | Print the most recent received message |
| `-deci <key>` | Decrypt the incoming message buffer |

## Notes

- AES-256 keys and peer addresses must be exchanged out-of-band.
- Messages are limited to **1280 characters**.
- IPv4 only (IPv6 is detected but not fully supported).

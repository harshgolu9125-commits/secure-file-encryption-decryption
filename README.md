# Secure File Encryption and Decryption

A Python-based secure file encryption and decryption system designed to protect digital files from unauthorized access.

## Abstract

This project provides a practical system for protecting digital files through secure encryption and controlled decryption. AES-256-GCM is used to encrypt the actual file data, while RSA-2048 protects the AES encryption key. PBKDF2-HMAC-SHA256 is used for password-based key derivation and verification. The system also supports file-status tracking, activity logging, failed-password control, and temporary locking.

## Key Features

- AES-256-GCM file encryption
- RSA-2048 AES key protection
- PBKDF2-HMAC-SHA256 password verification
- File encryption and decryption
- File status tracking
- Activity logging
- Failed password attempt control
- Temporary security lock
- Support for different file types

## Technologies Used

| Technology | Purpose |
|---|---|
| Python | Main programming language |
| AES-256-GCM | File encryption |
| RSA-2048 | AES key protection |
| PBKDF2-HMAC-SHA256 | Password security |
| Cryptography Library | Cryptographic operations |
| JSON | File status tracking |
| Activity Log | Security event recording |

## Working Process

User + File → Password Verification → PBKDF2-HMAC-SHA256 → AES-256-GCM Encryption → RSA-2048 Key Protection → Encrypted File → RSA-2048 Key Recovery → AES-256-GCM Decryption → Original File

## Project Structure

```text
project.py
public_key.pem
photo.jpg
photojpg.jpg
Report.pdf.pdf
Report3.pdf
test1.txt
test2.txt

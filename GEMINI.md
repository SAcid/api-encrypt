# Novel Content Encryption API Project

## Overview
This project demonstrates how to securely serve novel content via a REST API. The content is encrypted on the server implementation utilizing AES-256 and decrypted on various client platforms.

## Project Structure
- `backend`: Spring Boot 3.5 application (Java 21) exposing the REST API.
- `web`: Simple HTML/JS client demonstrating decryption in the browser.
- `ios`: Swift-based iOS client example.
- `android`: Kotlin-based Android client example.

## Tech Stack
- **Backend**: Java 21, Spring Boot 3.5, Spring MVC
- **Web**: HTML5, Vanilla JS, Web Crypto API
- **iOS**: Swift, CryptoKit
- **Android**: Kotlin, javax.crypto

## Key Features
- AES-256 Encryption (CBC/GCM modes to be decided, likely CBC for broad compatibility simplicity in example or GCM for security).
- Cross-platform decryption examples.

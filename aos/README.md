# Android Client Example

This directory contains Kotlin code demonstrating how to decrypt the AES-GCM encrypted content from the API.

## Requirements
- Android API Level 23+ (Android 6.0 Marshmallow) for GCM support.
- Kotlin 1.5+

## Usage
1. Copy `CryptoManager.kt` into your Android project.
2. Use `CryptoManager.decrypt(base64String)` to get the plaintext.

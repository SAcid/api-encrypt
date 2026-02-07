# iOS Client Example

This directory contains Swift code demonstrating how to decrypt the AES-GCM encrypted content from the API.

## Requirements
- iOS 13.0+
- Swift 5.0+
- Framework: `CryptoKit` (Built-in)

## Usage
1. Copy `CryptoManager.swift` into your Xcode project.
2. Use `CryptoManager.shared.decrypt(base64String:)` to decrypt the API response.

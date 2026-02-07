package com.example.novelapi.dto;

public record KeyExchangeRequest(String publicKey, long timestamp, String signature) {
}

package com.example.novelapi.dto;

/**
 * 클라이언트의 키 교환 요청 DTO
 * 
 * @param publicKey 클라이언트의 ECDH 공개키 (Base64)
 * @param timestamp 요청 생성 시간 (Replay Attack 방지)
 * @param signature 인증 서명 (HMAC-SHA256)
 */
public record KeyExchangeRequest(String publicKey, long timestamp, String signature) {
}

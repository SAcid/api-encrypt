package com.example.novelapi.service;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.HexFormat;

/**
 * Redis 기반 Replay Attack 방어 서비스.
 * 동일한 (publicKey, timestamp, salt) 조합의 요청이 재사용되는 것을 방지합니다.
 */
@Service
public class ReplayGuardService {

    private static final String KEY_PREFIX = "replay:";
    private static final Duration TTL = Duration.ofMinutes(5);

    private final StringRedisTemplate redisTemplate;

    public ReplayGuardService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    /**
     * 요청의 고유성을 검증합니다.
     * Redis SETNX를 사용하여 동일 Nonce가 이미 존재하면 false를 반환합니다.
     *
     * @param publicKey 클라이언트 공개키
     * @param timestamp 요청 타임스탬프
     * @param salt      클라이언트 Salt
     * @return true: 신규 요청 (통과), false: 중복 요청 (거부)
     */
    public boolean checkAndMark(String publicKey, long timestamp, String salt) {
        String nonce = publicKey + timestamp + salt;
        String hash = sha256(nonce);
        String key = KEY_PREFIX + hash;

        // SETNX: 키가 없으면 설정하고 true 반환, 이미 있으면 false 반환
        Boolean isNew = redisTemplate.opsForValue().setIfAbsent(key, "1", TTL);
        return Boolean.TRUE.equals(isNew);
    }

    private String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 hashing failed", e);
        }
    }
}

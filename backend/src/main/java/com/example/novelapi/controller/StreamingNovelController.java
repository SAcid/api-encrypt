package com.example.novelapi.controller;

import com.example.novelapi.dto.KeyExchangeRequest;

import com.example.novelapi.service.NovelStreamingService;
import com.example.novelapi.service.ReplayGuardService;
import com.example.novelapi.util.CryptoUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Base64;

/**
 * SSE(Server-Sent Events) 기반 스트리밍 소설 API 컨트롤러.
 * 소설 내용을 chunk 단위로 암호화하여 실시간 스트리밍합니다.
 *
 * 이벤트 흐름:
 * 1. init — 서버 공개키 + 타임스탬프 전송
 * 2. chunk — 암호화된 텍스트 조각 (index 포함)
 * 3. done — 스트림 종료 신호
 */
@RestController
@RequestMapping("/api/novels")
@CrossOrigin(origins = "*")
public class StreamingNovelController {

    @Value("${novel.client-secret}")
    private String clientSecret;

    private final ReplayGuardService replayGuardService;
    private final NovelStreamingService novelStreamingService;

    private static final long TIMESTAMP_LIMIT_MS = 5 * 60 * 1000;

    public StreamingNovelController(ReplayGuardService replayGuardService,
            NovelStreamingService novelStreamingService) {
        this.replayGuardService = replayGuardService;
        this.novelStreamingService = novelStreamingService;
    }

    /**
     * 스트리밍 소설 조회 API
     *
     * @param id        소설 챕터 ID
     * @param chunkSize chunk당 문자 수 (코드포인트 기준, 기본 100)
     * @param request   클라이언트 키 교환 요청
     * @return SseEmitter (SSE 스트림)
     */
    @PostMapping("/{id}/stream")
    public SseEmitter streamNovel(
            @PathVariable String id,
            @RequestParam(defaultValue = "100") int chunkSize,
            @RequestBody KeyExchangeRequest request) {

        // === 인증 검증 (기존 로직과 동일) ===

        // 1. 타임스탬프 검증
        long currentTime = System.currentTimeMillis();
        if (Math.abs(currentTime - request.timestamp()) > TIMESTAMP_LIMIT_MS) {
            throw new RuntimeException("Unauthorized");
        }

        // 2. HMAC 서명 검증
        try {
            String dataToSign = request.publicKey() + request.timestamp() + request.salt();
            String expectedSignature = CryptoUtil.generateHmacSignature(dataToSign, clientSecret);

            if (!java.security.MessageDigest.isEqual(
                    expectedSignature.getBytes(StandardCharsets.UTF_8),
                    request.signature().getBytes(StandardCharsets.UTF_8))) {
                throw new RuntimeException("Unauthorized");
            }
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Unauthorized");
        }

        // 3. Replay Attack 방어
        if (!replayGuardService.checkAndMark(request.publicKey(), request.timestamp(), request.salt())) {
            throw new RuntimeException("Unauthorized");
        }

        // === 키 교환 및 세션 키 유도 ===
        final KeyPair serverKeyPair;
        final SecretKey sessionKey;
        final String infoString;
        final String serverPublicKeyBase64;

        try {
            serverKeyPair = CryptoUtil.generateKeyPair();
            byte[] sharedSecret = CryptoUtil.computeSharedSecret(serverKeyPair.getPrivate(), request.publicKey());
            byte[] salt = Base64.getDecoder().decode(request.salt());

            infoString = "novel-id:" + id + "|ts:" + request.timestamp();
            byte[] info = infoString.getBytes(StandardCharsets.UTF_8);

            sessionKey = CryptoUtil.deriveKey(sharedSecret, salt, info);
            serverPublicKeyBase64 = Base64.getEncoder().encodeToString(serverKeyPair.getPublic().getEncoded());
        } catch (Exception e) {
            throw new RuntimeException("Encryption setup failed");
        }

        // === SSE 스트리밍 ===
        SseEmitter emitter = new SseEmitter(30_000L); // 30초 타임아웃

        // 비동기 서비스 호출 (@Async)
        novelStreamingService.streamNovelContent(
                emitter,
                serverPublicKeyBase64,
                request.timestamp(),
                sessionKey,
                infoString,
                chunkSize);

        return emitter;
    }
}

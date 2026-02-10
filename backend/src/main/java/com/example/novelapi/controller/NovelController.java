package com.example.novelapi.controller;

import com.example.novelapi.dto.KeyExchangeRequest;
import com.example.novelapi.dto.NovelResponse;
import com.example.novelapi.service.ReplayGuardService;
import com.example.novelapi.util.CryptoUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Base64;

/**
 * 소설 내용을 제공하는 REST 컨트롤러입니다.
 * ECDH 키 교환과 HMAC-SHA256 서명을 이용한 클라이언트 인증을 수행합니다.
 */
@RestController
@RequestMapping("/api/novels")
@CrossOrigin(origins = "*") // 데모 목적: 모든 도메인에서의 접근 허용
public class NovelController {

    // 클라이언트 인증을 위한 비밀 키 (환경 변수 NOVEL_CLIENT_SECRET 또는 application.properties에서 주입)
    @Value("${novel.client-secret}")
    private String clientSecret;

    private final ReplayGuardService replayGuardService;

    public NovelController(ReplayGuardService replayGuardService) {
        this.replayGuardService = replayGuardService;
    }

    // 타임스탬프 유효 시간 (5분): Replay Attack 방지
    private static final long TIMESTAMP_LIMIT_MS = 5 * 60 * 1000;

    /**
     * 소설 내용 조회 API (암호화 + 인증)
     * 
     * @param id      소설 챕터 ID
     * @param request 클라이언트의 공개키, 타임스탬프, 서명이 포함된 요청
     * @return 서버 공개키와 암호화된 소설 내용
     */
    @PostMapping("/{id}")
    public NovelResponse getNovel(@PathVariable String id, @RequestBody KeyExchangeRequest request) {
        // 1. 타임스탬프 검증 (Replay Attack 방지)
        long currentTime = System.currentTimeMillis();
        // 요청 시간이 현재 시간보다 5분 이상 차이가 나면 거부
        if (Math.abs(currentTime - request.timestamp()) > TIMESTAMP_LIMIT_MS) {
            System.err.println("Timestamp validation failed");
            throw new RuntimeException("Unauthorized");
        }

        // 2. 서명(Signature) 검증 (HMAC-SHA256)
        try {
            // 서명 대상 데이터: 공개키 + 타임스탬프 + Salt (무결성 강화)
            String dataToSign = request.publicKey() + request.timestamp() + request.salt();
            // 서버가 가진 Secret으로 서명 재계산
            String expectedSignature = CryptoUtil.generateHmacSignature(dataToSign, clientSecret);

            // 클라이언트가 보낸 서명과 일치하는지 확인 (Timing Attack 방지: MessageDigest.isEqual 사용)
            if (!java.security.MessageDigest.isEqual(
                    expectedSignature.getBytes(StandardCharsets.UTF_8),
                    request.signature().getBytes(StandardCharsets.UTF_8))) {
                // 민감 정보(expected 값) 노출 방지: 불일치 사실만 기록
                System.err.println("Signature verification failed for request timestamp=" + request.timestamp());
                throw new RuntimeException("Unauthorized");
            }
        } catch (RuntimeException e) {
            throw e; // Unauthorized 예외는 그대로 전파
        } catch (Exception e) {
            System.err.println("Signature verification error: " + e.getClass().getSimpleName());
            throw new RuntimeException("Unauthorized");
        }

        // 3. Replay Attack 방어 (Redis Nonce 검증)
        if (!replayGuardService.checkAndMark(request.publicKey(), request.timestamp(), request.salt())) {
            System.err.println("Replay attack detected for request timestamp=" + request.timestamp());
            throw new RuntimeException("Unauthorized");
        }

        // 원본 소설 내용
        String originalContent = """
                제1장: 시작의 검

                그는 검을 들었다. 무거운 강철의 차가움이 손바닥을 통해 전해졌다.
                "이것이... 나의 운명인가."
                바람이 불어와 그의 머리카락을 쓸어 넘겼다. 저 멀리서 몬스터들의 포효가 들려왔다.
                준비는 끝났다. 이제 모험을 시작할 시간이다.
                (보안 강화됨: ECDH Key Exchange + Client Auth)
                """;

        try {
            // 3. 서버의 임시(Ephemeral) ECDH 키 쌍 생성
            KeyPair serverKeyPair = CryptoUtil.generateKeyPair();

            // 4. 공유 비밀(Shared Secret) 계산 (Server Private Key + Client Public Key)
            byte[] sharedSecret = CryptoUtil.computeSharedSecret(serverKeyPair.getPrivate(), request.publicKey());

            // 5. AES 세션 키 유도 (HKDF 사용)
            // 5-1. Salt 추출 (Client Nonce)
            byte[] salt = Base64.getDecoder().decode(request.salt());

            // 5-2. Info 생성 (Context Binding: novel-id + timestamp)
            // 클라이언트가 보낸 timestamp를 사용하여 요청별 고유 컨텍스트 생성
            String infoString = "novel-id:" + id + "|ts:" + request.timestamp();
            byte[] info = infoString.getBytes(StandardCharsets.UTF_8);

            SecretKey sessionKey = CryptoUtil.deriveKey(sharedSecret, salt, info);

            // 6. 세션 키로 내용 암호화 (AES-GCM)
            // AAD로 Context Info를 사용하여 암호문에 컨텍스트 바인딩 (Context Binding)
            String encryptedContent = CryptoUtil.encrypt(originalContent, sessionKey, info);

            // 7. 응답 생성 (서버 공개키 + 암호화된 내용 + timestamp)
            String serverPublicKeyBase64 = Base64.getEncoder().encodeToString(serverKeyPair.getPublic().getEncoded());

            return new NovelResponse(serverPublicKeyBase64, encryptedContent, request.timestamp());

        } catch (Exception e) {
            System.err.println("Encryption processing error: " + e.getClass().getSimpleName());
            throw new RuntimeException("Encryption failed");
        }
    }
}

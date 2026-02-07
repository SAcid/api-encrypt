package com.example.novelapi.controller;

import com.example.novelapi.dto.KeyExchangeRequest;
import com.example.novelapi.dto.NovelResponse;
import com.example.novelapi.util.CryptoUtil;
import org.springframework.web.bind.annotation.*;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
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

    // 클라이언트 인증을 위한 비밀 키 (실무에서는 환경 변수나 보안 저장소에 보관해야 함)
    private static final String CLIENT_SECRET = "auth-secret-1234";

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
            throw new RuntimeException("Unauthorized: Timestamp expired (인증 실패: 요청 시간 만료)");
        }

        // 2. 서명(Signature) 검증 (HMAC-SHA256)
        try {
            // 서명 대상 데이터: 공개키 + 타임스탬프
            String dataToSign = request.publicKey() + request.timestamp();
            // 서버가 가진 Secret으로 서명 재계산
            String expectedSignature = hmacSha256(dataToSign, CLIENT_SECRET);

            // 클라이언트가 보낸 서명과 일치하는지 확인
            if (!expectedSignature.equals(request.signature())) {
                throw new RuntimeException("Unauthorized: Invalid Signature (인증 실패: 서명 불일치)");
            }
        } catch (Exception e) {
            throw new RuntimeException("Unauthorized: Signature verification failed (인증 실패: 서명 검증 오류)");
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

            // 5-2. Info 생성 (Context Binding: novel-id + user-id)
            // 예: "novel-id:123|user:test"
            String infoString = "novel-id:" + id + "|user:test";
            byte[] info = infoString.getBytes(StandardCharsets.UTF_8);

            SecretKey sessionKey = CryptoUtil.deriveKey(sharedSecret, salt, info);

            // 6. 세션 키로 내용 암호화 (AES-GCM)
            String encryptedContent = CryptoUtil.encrypt(originalContent, sessionKey);

            // 7. 응답 생성 (서버 공개키 + 암호화된 내용)
            String serverPublicKeyBase64 = Base64.getEncoder().encodeToString(serverKeyPair.getPublic().getEncoded());

            return new NovelResponse(serverPublicKeyBase64, encryptedContent);

        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Encryption failed (암호화 실패): " + e.getMessage());
        }
    }

    /**
     * HMAC-SHA256 서명을 생성하는 유틸리티 메서드
     */
    private String hmacSha256(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] rawHmac = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(rawHmac);
    }
}

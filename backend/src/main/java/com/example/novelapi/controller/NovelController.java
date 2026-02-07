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

@RestController
@RequestMapping("/api/novels")
@CrossOrigin(origins = "*") // Allow all for demo
public class NovelController {

    private static final String CLIENT_SECRET = "auth-secret-1234";
    private static final long TIMESTAMP_LIMIT_MS = 5 * 60 * 1000; // 5 minutes

    @PostMapping("/{id}")
    public NovelResponse getNovel(@PathVariable String id, @RequestBody KeyExchangeRequest request) {
        // 1. Validate Timestamp (Replay Attack Prevention)
        long currentTime = System.currentTimeMillis();
        if (Math.abs(currentTime - request.timestamp()) > TIMESTAMP_LIMIT_MS) {
            throw new RuntimeException("Unauthorized: Timestamp expired");
        }

        // 2. Validate Signature (HMAC-SHA256)
        try {
            String dataToSign = request.publicKey() + request.timestamp();
            String expectedSignature = hmacSha256(dataToSign, CLIENT_SECRET);

            if (!expectedSignature.equals(request.signature())) {
                throw new RuntimeException("Unauthorized: Invalid Signature");
            }
        } catch (Exception e) {
            throw new RuntimeException("Unauthorized: Signature verification failed");
        }

        String originalContent = """
                제1장: 시작의 검

                그는 검을 들었다. 무거운 강철의 차가움이 손바닥을 통해 전해졌다.
                "이것이... 나의 운명인가."
                바람이 불어와 그의 머리카락을 쓸어 넘겼다. 저 멀리서 몬스터들의 포효가 들려왔다.
                준비는 끝났다. 이제 모험을 시작할 시간이다.
                (보안 강화됨: ECDH Key Exchange + Client Auth)
                """;

        try {
            // 3. Generate Ephemeral Server Key Pair
            KeyPair serverKeyPair = CryptoUtil.generateKeyPair();

            // 4. Compute Shared Secret
            byte[] sharedSecret = CryptoUtil.computeSharedSecret(serverKeyPair.getPrivate(), request.publicKey());

            // 5. Derive AES Key
            SecretKey sessionKey = CryptoUtil.deriveKey(sharedSecret);

            // 6. Encrypt Content using Session Key
            String encryptedContent = CryptoUtil.encrypt(originalContent, sessionKey);

            // 7. Return Server Public Key + Encrypted Content
            String serverPublicKeyBase64 = Base64.getEncoder().encodeToString(serverKeyPair.getPublic().getEncoded());

            return new NovelResponse(serverPublicKeyBase64, encryptedContent);

        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Encryption failed: " + e.getMessage());
        }
    }

    private String hmacSha256(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] rawHmac = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(rawHmac);
    }
}

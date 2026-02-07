package com.example.novelapi.controller;

import com.example.novelapi.dto.KeyExchangeRequest;
import com.example.novelapi.dto.NovelResponse;
import com.example.novelapi.util.CryptoUtil;
import org.springframework.web.bind.annotation.*;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.util.Base64;

@RestController
@RequestMapping("/api/novels")
@CrossOrigin(origins = "*") // Allow all for demo
public class NovelController {

    @PostMapping("/{id}")
    public NovelResponse getNovel(@PathVariable String id, @RequestBody KeyExchangeRequest request) {
        String originalContent = """
                제1장: 시작의 검

                그는 검을 들었다. 무거운 강철의 차가움이 손바닥을 통해 전해졌다.
                "이것이... 나의 운명인가."
                바람이 불어와 그의 머리카락을 쓸어 넘겼다. 저 멀리서 몬스터들의 포효가 들려왔다.
                준비는 끝났다. 이제 모험을 시작할 시간이다.
                (보안 강화됨: ECDH Key Exchange)
                """;

        try {
            // 1. Generate Ephemeral Server Key Pair
            KeyPair serverKeyPair = CryptoUtil.generateKeyPair();

            // 2. Compute Shared Secret
            byte[] sharedSecret = CryptoUtil.computeSharedSecret(serverKeyPair.getPrivate(), request.publicKey());

            // 3. Derive AES Key
            SecretKey sessionKey = CryptoUtil.deriveKey(sharedSecret);

            // 4. Encrypt Content using Session Key
            String encryptedContent = CryptoUtil.encrypt(originalContent, sessionKey);

            // 5. Return Server Public Key + Encrypted Content
            String serverPublicKeyBase64 = Base64.getEncoder().encodeToString(serverKeyPair.getPublic().getEncoded());

            return new NovelResponse(serverPublicKeyBase64, encryptedContent);

        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Encryption failed: " + e.getMessage());
        }
    }
}

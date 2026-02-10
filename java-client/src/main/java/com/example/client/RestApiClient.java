package com.example.client;

import com.example.novelapi.util.CryptoUtil;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.*;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Base64;
import java.util.UUID;

/**
 * 단일 REST API (/api/novels/{id}) 호출 예제
 */
public class RestApiClient {
    private static final String SERVER_URL = "http://localhost:8080/api/novels/1";
    // 주의: 실제 환경에서는 안전하게 관리해야 함
    private static final String CLIENT_SECRET = "auth-secret-1234";

    private final OkHttpClient client = new OkHttpClient();
    private final ObjectMapper mapper = new ObjectMapper();

    public static void main(String[] args) {
        try {
            new RestApiClient().run();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void run() throws Exception {
        System.out.println("=== REST API Client Start ===");

        // 1. 클라이언트 키 쌍(ECDH) 생성
        KeyPair clientKeyPair = CryptoUtil.generateKeyPair();
        String clientPublicKey = Base64.getEncoder().encodeToString(clientKeyPair.getPublic().getEncoded());

        // 2. 인증 데이터 생성
        long timestamp = System.currentTimeMillis();
        String salt = Base64.getEncoder().encodeToString(UUID.randomUUID().toString().getBytes());
        String dataToSign = clientPublicKey + timestamp + salt;
        String signature = CryptoUtil.generateHmacSignature(dataToSign, CLIENT_SECRET);

        // 3. 요청 JSON 구성
        String jsonBody = String.format(
                "{\"publicKey\":\"%s\",\"timestamp\":%d,\"signature\":\"%s\",\"salt\":\"%s\"}",
                clientPublicKey, timestamp, signature, salt);

        RequestBody body = RequestBody.create(jsonBody, MediaType.get("application/json; charset=utf-8"));
        Request request = new Request.Builder()
                .url(SERVER_URL)
                .post(body)
                .build();

        // 4. API 호출
        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Unexpected code " + response);
            }

            String responseBody = response.body().string();
            JsonNode rootNode = mapper.readTree(responseBody);

            String serverPublicKey = rootNode.get("publicKey").asText();
            String encryptedContent = rootNode.get("content").asText();

            System.out.println("Server Public Key: " + serverPublicKey);
            System.out.println("Encrypted Content: " + encryptedContent);

            // 5. 키 유도 (ECDH + HKDF)
            byte[] sharedSecret = CryptoUtil.computeSharedSecret(clientKeyPair.getPrivate(), serverPublicKey);
            byte[] saltBytes = Base64.getDecoder().decode(salt);

            // Context Binding (novel-id:1|ts:{timestamp})
            String novelId = "1";
            String infoString = "novel-id:" + novelId + "|ts:" + timestamp;
            byte[] infoBytes = infoString.getBytes(StandardCharsets.UTF_8);

            SecretKey sessionKey = CryptoUtil.deriveKey(sharedSecret, saltBytes, infoBytes);

            // 6. 복호화
            // AAD (Context Binding)
            byte[] aad = infoBytes;
            String decrypted = CryptoUtil.decrypt(encryptedContent, sessionKey, aad);

            System.out.println("\n--- Decrypted Content ---");
            System.out.println(decrypted);
            System.out.println("-------------------------");
        }
    }
}

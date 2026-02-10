package com.example.client;

import com.example.novelapi.util.CryptoUtil;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.*;
import okhttp3.sse.EventSource;
import okhttp3.sse.EventSourceListener;
import okhttp3.sse.EventSources;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * SSE 스트리밍 API (/api/novels/{id}/stream) 호출 예제
 */
public class StreamingApiClient {
    private static final String SERVER_URL = "http://localhost:8080/api/novels/1/stream";
    private static final String CLIENT_SECRET = "auth-secret-1234";

    private final OkHttpClient client;
    private final ObjectMapper mapper = new ObjectMapper();
    private final CountDownLatch latch = new CountDownLatch(1);

    // Session State
    private KeyPair clientKeyPair;
    private SecretKey sessionKey;
    private byte[] aad;

    public StreamingApiClient() {
        this.client = new OkHttpClient.Builder()
                .readTimeout(0, TimeUnit.MILLISECONDS) // SSE: No timeout
                .build();
    }

    public static void main(String[] args) {
        try {
            new StreamingApiClient().run();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void run() throws Exception {
        System.out.println("=== Streaming Client Start ===");

        // 1. 초기 키 생성 및 인증 준비
        clientKeyPair = CryptoUtil.generateKeyPair();
        String clientPublicKey = Base64.getEncoder().encodeToString(clientKeyPair.getPublic().getEncoded());
        long timestamp = System.currentTimeMillis();
        String salt = Base64.getEncoder().encodeToString(UUID.randomUUID().toString().getBytes());

        String dataToSign = clientPublicKey + timestamp + salt;
        String signature = CryptoUtil.generateHmacSignature(dataToSign, CLIENT_SECRET);

        String jsonBody = String.format(
                "{\"publicKey\":\"%s\",\"timestamp\":%d,\"signature\":\"%s\",\"salt\":\"%s\"}",
                clientPublicKey, timestamp, signature, salt);

        // 2. SSE 요청 (POST)
        Request request = new Request.Builder()
                .url(SERVER_URL)
                .post(RequestBody.create(jsonBody, MediaType.get("application/json")))
                .build();

        // 3. SSE 연결
        EventSource.Factory factory = EventSources.createFactory(client);
        factory.newEventSource(request, new NovelEventListener(timestamp, salt));

        // 종료 대기
        latch.await();
        System.out.println("=== Streaming Finished ===");

        // 스레드 풀 종료 (main 종료를 위해)
        client.dispatcher().executorService().shutdown();
    }

    private class NovelEventListener extends EventSourceListener {
        private final long timestamp;
        private final String saltBase64;

        public NovelEventListener(long timestamp, String saltBase64) {
            this.timestamp = timestamp;
            this.saltBase64 = saltBase64;
        }

        @Override
        public void onOpen(EventSource eventSource, Response response) {
            System.out.println("Connection Opened");
        }

        @Override
        public void onEvent(EventSource eventSource, String id, String type, String data) {
            try {
                if ("init".equals(type)) {
                    handleInit(data);
                } else if ("chunk".equals(type)) {
                    handleChunk(data);
                } else if ("done".equals(type)) {
                    System.out.println("\n[DONE] " + data);
                    latch.countDown();
                }
            } catch (Exception e) {
                e.printStackTrace();
                latch.countDown();
            }
        }

        @Override
        public void onClosed(EventSource eventSource) {
            System.out.println("Connection Closed");
            latch.countDown();
        }

        @Override
        public void onFailure(EventSource eventSource, Throwable t, Response response) {
            System.err.println("Error: " + t.getMessage());
            latch.countDown();
        }

        private void handleInit(String data) throws Exception {
            JsonNode root = mapper.readTree(data);
            String serverPublicKeyBase64 = root.get("publicKey").asText();
            int totalChunks = root.get("totalChunks").asInt();

            System.out.println("[INIT] Server Key Received. Total Chunks: " + totalChunks);

            // ECDH + HKDF -> Session Key Derivation
            byte[] sharedSecret = CryptoUtil.computeSharedSecret(clientKeyPair.getPrivate(), serverPublicKeyBase64);
            byte[] saltBytes = Base64.getDecoder().decode(saltBase64);

            String novelId = "1";
            String infoString = "novel-id:" + novelId + "|ts:" + timestamp;
            byte[] infoBytes = infoString.getBytes(StandardCharsets.UTF_8);

            sessionKey = CryptoUtil.deriveKey(sharedSecret, saltBytes, infoBytes);
            aad = infoBytes; // Store AAD for chunk decryption

            System.out.println("[INIT] Session Key Derived.");
        }

        private void handleChunk(String data) throws Exception {
            if (sessionKey == null) {
                System.err.println("Session key not initialized yet!");
                return;
            }

            JsonNode root = mapper.readTree(data);
            int index = root.get("index").asInt();
            String encryptedContent = root.get("content").asText();

            String plaintext = CryptoUtil.decrypt(encryptedContent, sessionKey, aad);
            System.out.print(plaintext); // 줄바꿈 없이 출력하여 이어붙이기
        }
    }
}

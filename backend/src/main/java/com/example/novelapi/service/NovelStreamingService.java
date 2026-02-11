package com.example.novelapi.service;

import com.example.novelapi.util.ChunkUtil;
import com.example.novelapi.util.CryptoUtil;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.List;

@Service
public class NovelStreamingService {

    /**
     * 비동기로 소설 내용을 스트리밍합니다.
     * 별도의 스레드 풀(AsyncConfig에서 설정된 taskExecutor)에서 실행됩니다.
     */
    @Async("taskExecutor")
    public void streamNovelContent(SseEmitter emitter, String serverPublicKeyBase64, long timestamp,
            SecretKey sessionKey, String infoString, int chunkSize) {
        try {
            // 원본 소설 내용
            String originalContent = """
                    제1장: 시작의 검

                    그는 검을 들었다. 무거운 강철의 차가움이 손바닥을 통해 전해졌다.
                    "이것이... 나의 운명인가."
                    바람이 불어와 그의 머리카락을 쓸어 넘겼다. 저 멀리서 몬스터들의 포효가 들려왔다.
                    준비는 끝났다. 이제 모험을 시작할 시간이다.

                    제2장: 첫 번째 전투

                    숲 속에서 갑자기 나타난 고블린 무리. 그 수는 열 마리가 넘었다.
                    "좋아, 이 정도면 워밍업으로 딱이군."
                    그는 검을 휘둘렀다. 빛이 번쩍이며 고블린 세 마리가 동시에 쓰러졌다.
                    나머지 고블린들이 잠시 주춤했지만, 이내 분노에 찬 눈으로 달려들었다.
                    하지만 그의 검술 앞에 그들은 하나둘 쓰러져갔다.

                    "레벨업... 했나?"
                    (보안 강화됨: Async Streaming + ECDH + AES-GCM Chunk Encryption)
                    """;

            // 코드포인트 기반 한글 인식 분할
            List<String> chunks = ChunkUtil.splitByCodePoints(originalContent, chunkSize);
            byte[] aad = infoString.getBytes(StandardCharsets.UTF_8);

            // Event 1: init (서버 공개키 전송)
            String initData = String.format(
                    "{\"publicKey\":\"%s\",\"totalChunks\":%d}",
                    serverPublicKeyBase64, chunks.size());
            emitter.send(SseEmitter.event().name("init").data(initData));

            // Event 2..N: chunk (암호화된 텍스트 조각)
            for (int i = 0; i < chunks.size(); i++) {
                String encryptedChunk = CryptoUtil.encrypt(chunks.get(i), sessionKey, aad);
                String chunkData = String.format(
                        "{\"index\":%d,\"content\":\"%s\"}", i, encryptedChunk);
                emitter.send(SseEmitter.event().name("chunk").data(chunkData));

            }

            // Event N+1: done
            String doneData = String.format("{\"totalChunks\":%d}", chunks.size());
            emitter.send(SseEmitter.event().name("done").data(doneData));

            emitter.complete();
        } catch (Exception e) {
            emitter.completeWithError(e);
        }
    }
}

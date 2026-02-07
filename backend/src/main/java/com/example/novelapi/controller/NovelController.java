package com.example.novelapi.controller;

import com.example.novelapi.util.CryptoUtil;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/novels")
public class NovelController {

    @GetMapping("/{id}")
    public Map<String, String> getNovel(@PathVariable String id) {
        // Mock content. In a real app, this would come from a database.
        String originalContent = """
                제1장: 시작의 검

                그는 검을 들었다. 무거운 강철의 차가움이 손바닥을 통해 전해졌다.
                "이것이... 나의 운명인가."
                바람이 불어와 그의 머리카락을 쓸어 넘겼다. 저 멀리서 몬스터들의 포효가 들려왔다.
                준비는 끝났다. 이제 모험을 시작할 시간이다.
                """;

        try {
            String encryptedContent = CryptoUtil.encrypt(originalContent);
            return Map.of(
                    "id", id,
                    "content", encryptedContent);
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }
}

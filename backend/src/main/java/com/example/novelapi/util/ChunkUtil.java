package com.example.novelapi.util;

import java.util.ArrayList;
import java.util.List;

/**
 * 텍스트를 코드포인트(Unicode Code Point) 단위로 안전하게 분할하는 유틸리티.
 * 한글, 이모지 등 멀티바이트 문자가 중간에서 잘리지 않도록 보장합니다.
 */
public class ChunkUtil {

    /**
     * 텍스트를 지정된 문자 수(코드포인트 수) 단위로 분할합니다.
     *
     * @param text      분할할 텍스트
     * @param chunkSize chunk당 최대 문자 수 (코드포인트 기준)
     * @return 분할된 텍스트 리스트
     */
    public static List<String> splitByCodePoints(String text, int chunkSize) {
        if (text == null || text.isEmpty()) {
            return List.of();
        }
        if (chunkSize <= 0) {
            throw new IllegalArgumentException("chunkSize must be positive");
        }

        List<String> chunks = new ArrayList<>();
        int length = text.length(); // UTF-16 단위 길이
        int offset = 0;

        while (offset < length) {
            // 현재 offset부터 chunkSize개의 코드포인트를 계산
            int codePointCount = 0;
            int end = offset;

            while (end < length && codePointCount < chunkSize) {
                int cp = text.codePointAt(end);
                end += Character.charCount(cp); // surrogate pair 대응
                codePointCount++;
            }

            chunks.add(text.substring(offset, end));
            offset = end;
        }

        return chunks;
    }
}

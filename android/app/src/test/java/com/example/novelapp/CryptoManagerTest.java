package com.example.novelapp;

import org.junit.Test;
import static org.junit.Assert.*;

public class CryptoManagerTest {

    @Test
    public void testAuthSignatureGeneration() {
        String publicKey = "testPublicKey";
        kotlin.Pair<Long, String> auth = CryptoManager.INSTANCE.generateAuth(publicKey);

        long timestamp = auth.getFirst();
        String signature = auth.getSecond();

        assertTrue(timestamp > 0);
        assertNotNull(signature);
        assertFalse(signature.isEmpty());

        System.out.println("Timestamp: " + timestamp);
        System.out.println("Signature: " + signature);
    }
}

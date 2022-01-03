package com.anhdungpham;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

@SpringBootTest
class Oauth2SpringAuthorizationServerApplicationTests {

    @Test
    void code_verifier() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] code = new byte[32];
        secureRandom.nextBytes(code);

        String code_verifier = Base64.getUrlEncoder().withoutPadding().encodeToString(code);

        System.out.println(code_verifier);
    }

    @Test
    void messageDigest() {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            byte[] digestCode = messageDigest.digest("change_your_verification_code".getBytes());
            String code_challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(digestCode);
            System.out.println(code_challenge);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}

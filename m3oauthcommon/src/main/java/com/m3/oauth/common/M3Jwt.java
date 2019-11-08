package com.m3.oauth.common;

public interface M3Jwt {
    String claims();
    String encoded();
    byte[] bytesWithoutSignature();
    byte[] signature();

    default boolean verifySignature(M3SignatureVerifier verifier) {
        byte[] basebytes = bytesWithoutSignature();
        return verifier.verify(basebytes, signature());
    }

    String AUDIENCE = "aud";
}

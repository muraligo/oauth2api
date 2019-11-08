package com.m3.oauth.common;

public interface M3SignatureVerifier {
    String algorithm(); // JCA/JCE algorithm name
    boolean verify(byte[] content, byte[] signature);
}

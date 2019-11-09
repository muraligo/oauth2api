package com.m3.ouath.service.handler;

import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class RsaSigner {
    private static final String DEFAULT_ALGORITHM = "SHA256withRSA";
    private static final String KEY_DEFAULT_ALGORITHM = "RS256";
    private static final Map<String, String> _SIGNATURE_ALGORITHMS = new ConcurrentHashMap<String, String>();
    private static final Map<String, String> _JAVA_SIGN_ALGORITHMS = new ConcurrentHashMap<String, String>();
    static {
        _SIGNATURE_ALGORITHMS.put(KEY_DEFAULT_ALGORITHM, DEFAULT_ALGORITHM);
        _SIGNATURE_ALGORITHMS.put("RS512", "SHA512withRSA");
        _JAVA_SIGN_ALGORITHMS.put(DEFAULT_ALGORITHM, KEY_DEFAULT_ALGORITHM);
        _JAVA_SIGN_ALGORITHMS.put("SHA512withRSA", "RS512");
    }

    // FIXME Later change both below to final
    private RSAPrivateKey _key;
    private String _algorithm;

	// FIXME Change from class to interface for provider
    public RsaSigner(SimpleRsaKeyProvider kp) {
		// FIXME Auto-generated constructor stub
    }

    public String algorithm() { return _algorithm; }

    public byte[] sign(byte[] data) {
        try {
            Signature signature = Signature.getInstance(_algorithm);
            signature.initSign(_key);
            signature.update(data);
            return signature.sign();
        } catch (GeneralSecurityException ex) {
            throw new RuntimeException(ex);
        }
    }

    static String signatureAlgorithm(String javaname) {
        String alg = _JAVA_SIGN_ALGORITHMS.get(javaname);
        if (alg == null) {
            throw new IllegalArgumentException("Invalid or unsupported signature algorithm");
        }
        return alg;
    }
}

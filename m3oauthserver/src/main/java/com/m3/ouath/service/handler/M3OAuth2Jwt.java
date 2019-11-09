package com.m3.ouath.service.handler;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import com.m3.oauth.common.M3Jwt;

class M3OAuth2Jwt implements M3Jwt {
    private static RsaSigner _signer = null;

    final M3JwtHeader _header;
    private final byte[] _content;
    private byte[] _crypto;
    private String _claims;

    M3OAuth2Jwt(M3JwtHeader hdr, byte[] claims, byte[] crypto) {
        _header = hdr;
        _content = claims;
        _crypto = crypto;
    }

    M3OAuth2Jwt(M3JwtHeader jwthdr, byte[] claimsb) {
        _header = jwthdr;
        _content = claimsb;
        byte[] presigbytes = bytesWithoutSignature();
        _crypto = _signer.sign(presigbytes);
    }

    @Override
    public String claims() { return _claims; }

    @Override
    public byte[] signature() { return _crypto; }

    @Override
    public String encoded() {
        String UTF8PERIOD = new String(".".getBytes(), StandardCharsets.UTF_8);
        String strenchdrs = new String(Base64.getEncoder().encode(_header._bytes), StandardCharsets.UTF_8);
        String strencclms = new String(Base64.getEncoder().encode(_content), StandardCharsets.UTF_8);
        String strenccrypto = new String(Base64.getEncoder().encode(_crypto), StandardCharsets.UTF_8);
        return (strenchdrs + UTF8PERIOD + strencclms + UTF8PERIOD + strenccrypto);
    }

    @Override
    public byte[] bytesWithoutSignature() {
        byte[] b64enc_hdrs = Base64.getEncoder().encode(_header._bytes);
        byte[] b64enc_clms = Base64.getEncoder().encode(_content);
        byte[] concatbytes = null;
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            baos.write(b64enc_hdrs);
            baos.write(Base64.getEncoder().encode(".".getBytes(StandardCharsets.UTF_8)));
            baos.write(b64enc_clms);
            concatbytes = baos.toByteArray();
        } catch (IOException ioe) {
            throw new RuntimeException("Error concatenating parts of JWT byte streams");
        }
        return concatbytes;
    }

    static class M3JwtHeader {
        final byte[] _bytes;
        final String _alg;
        final Map<String, String> _map;
        final String _typ = "JWT";

        M3JwtHeader(byte[] bytes, String alg) {
            this(bytes, new LinkedHashMap<String, String>(Collections.singletonMap("alg", alg)));
        }

        M3JwtHeader(Map<String, String> map) {
            this(serializeParams(map), map);
        }

        M3JwtHeader(byte[] bytes, Map<String, String> map) {
            _bytes = bytes;
            String alg = map.get("alg"), typ = map.get("typ");
            if (typ != null && !"JWT".equals(typ)) {
                throw new IllegalArgumentException("The typ needs to be JWT");
            }
            if (alg == null || alg.isBlank()) {
                throw new IllegalArgumentException("alg is required");
            }
            map.remove("typ");
            map.remove("alg");
            _map = map;
            _alg = alg;
        }
    }

    private static byte[] serializeParams(Map<String, String> params) {
        boolean firsttime = true;
        StringBuilder sb = new StringBuilder("{");
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (firsttime) firsttime = false;
            else sb.append(",");
            sb.append("\"");
            sb.append(entry.getKey());
            sb.append("\":\"");
            sb.append(entry.getValue());
            sb.append("\"");
        }
        sb.append("}");
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    public static String encodeJwtToUrlUtf8(String clientid, String requestpath,
            String audience, Long expiryseconds, String sshkeyfile) {
    	StringBuilder sb = new StringBuilder("{\"");
    	sb.append(ISSUER);
    	sb.append("\":\"");
    	sb.append(requestpath);
    	sb.append("\",\"");
    	sb.append(SUBJECT);
    	sb.append("\":\"");
    	sb.append(clientid);
    	sb.append("\",\"");
    	sb.append(AUDIENCE);
    	sb.append("\":\"");
    	sb.append(audience);
    	sb.append("\",\"");
    	sb.append(EXPIRATION);
    	sb.append("\":\"");
    	sb.append(expiryseconds.toString());
    	sb.append("}");
    	String strclaims = sb.toString();
    	if (_signer == null) {
    	    // start with simple and later change
    	    SimpleRsaKeyProvider kp = new SimpleRsaKeyProvider(sshkeyfile);
    	    _signer = new RsaSigner(kp);
    	}
    	Map<String, String> hdrmap = new LinkedHashMap<String, String>();
    	hdrmap.put("alg", RsaSigner.signatureAlgorithm(_signer.algorithm()));
    	M3JwtHeader jwthdr = new M3JwtHeader(hdrmap);
    	byte[] claimsb = strclaims.getBytes(StandardCharsets.UTF_8);
    	if (claimsb == null || claimsb.length == 0) {
    	    throw new RuntimeException("Error encoding body");
    	}
        M3OAuth2Jwt jwtobj = new M3OAuth2Jwt(jwthdr, claimsb);
        return URLEncoder.encode(jwtobj.encoded(), StandardCharsets.UTF_8);
    }
}

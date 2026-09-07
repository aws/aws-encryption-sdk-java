package com.amazonaws.encryptionsdk.internal;

import javax.crypto.Mac;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

public enum MacAlgorithm {
    HmacSHA256("HmacSHA256"),
    HmacSHA384("HmacSHA384"),
    HmacSHA512("HmacSHA512"),
    HkdfSHA512("HkdfSHA512"),
    HmacSHA1("HmacSHA1");
    private final String algorithm;
    private Provider provider;

    MacAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    Provider getProvider() throws NoSuchAlgorithmException {
        Provider provider = this.provider;
        if (provider == null) {
            provider = Mac.getInstance(algorithm).getProvider();
            this.provider = provider;
        }
        return provider;
    }

    String getAlgorithm() {
        return algorithm;
    }
}

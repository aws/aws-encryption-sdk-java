package aws.cryptography.esdk.testserver.server.registry;

import aws.cryptography.esdk.testserver.server.error.EsdkClientException;
import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.CryptoInputStream;
import com.amazonaws.encryptionsdk.CryptoMaterialsManager;
import com.amazonaws.encryptionsdk.CryptoResult;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Collections;
import java.util.Map;
import software.amazon.cryptography.materialproviders.ICryptographicMaterialsManager;

/**
 * A configured {@link EsdkClient} backed by the REAL AWS Encryption SDK for Java.
 * It pairs an {@link AwsCrypto} configuration (commitment policy, optional max
 * encrypted data keys) with a real cryptographic materials manager built from the
 * modeled config by {@code EsdkClientFactory}: a Material Providers Library CMM, or,
 * for the Caching CMM, the ESDK's own {@link CryptoMaterialsManager}
 * ({@code CachingCryptoMaterialsManager}), which wraps master key providers.
 *
 * <p>Every call reaches the real ESDK. Any exception the ESDK throws is caught and
 * rethrown as an {@link EsdkClientException} so the operation wrapper forwards it
 * as an {@code ESDKClientError} carrying the ESDK message unmodified (Requirements
 * 4.10, 5.6). The Java ESDK is Streaming_Capable, so the stream methods delegate
 * to the streaming API (Requirements 4.5, 4.6).
 */
public final class RealEsdkClient implements EsdkClient {

    private final CommitmentPolicy commitmentPolicy;
    private final Integer maxEncryptedDataKeys;
    /** Exactly one of {@code cmm} and {@code legacyCmm} is set. */
    private final ICryptographicMaterialsManager cmm;
    private final CryptoMaterialsManager legacyCmm;

    public RealEsdkClient(CommitmentPolicy commitmentPolicy,
                          Integer maxEncryptedDataKeys,
                          ICryptographicMaterialsManager cmm) {
        this(commitmentPolicy, maxEncryptedDataKeys, cmm, null);
    }

    public RealEsdkClient(CommitmentPolicy commitmentPolicy,
                          Integer maxEncryptedDataKeys,
                          CryptoMaterialsManager legacyCmm) {
        this(commitmentPolicy, maxEncryptedDataKeys, null, legacyCmm);
    }

    private RealEsdkClient(CommitmentPolicy commitmentPolicy, Integer maxEncryptedDataKeys,
                           ICryptographicMaterialsManager cmm, CryptoMaterialsManager legacyCmm) {
        this.commitmentPolicy = commitmentPolicy;
        this.maxEncryptedDataKeys = maxEncryptedDataKeys;
        this.cmm = cmm;
        this.legacyCmm = legacyCmm;
    }

    @Override
    public byte[] encrypt(byte[] plaintext, Map<String, String> encryptionContext,
                          String algorithmSuiteId, Long frameLength) throws EsdkClientException {
        try {
            AwsCrypto crypto = buildCrypto(algorithmSuiteId, frameLength);
            CryptoResult<byte[], ?> result = legacyCmm != null
                ? crypto.encryptData(legacyCmm, plaintext, nonNull(encryptionContext))
                : crypto.encryptData(cmm, plaintext, nonNull(encryptionContext));
            return result.getResult();
        } catch (Exception esdkFailure) {
            throw new EsdkClientException(esdkFailure);
        }
    }

    @Override
    public byte[] decrypt(byte[] ciphertext, Map<String, String> encryptionContext)
        throws EsdkClientException {
        try {
            AwsCrypto crypto = buildCrypto(null, null);
            Map<String, String> ec = nonNull(encryptionContext);
            if (legacyCmm != null) {
                requireNoReproducedContext(ec);
                return crypto.decryptData(legacyCmm, ciphertext).getResult();
            }
            CryptoResult<byte[], ?> result = ec.isEmpty()
                ? crypto.decryptData(cmm, ciphertext)
                : crypto.decryptData(cmm, ciphertext, ec);
            return result.getResult();
        } catch (Exception esdkFailure) {
            throw new EsdkClientException(esdkFailure);
        }
    }

    @Override
    public void encryptStream(InputStream plaintext, OutputStream ciphertext,
                              Map<String, String> encryptionContext,
                              String algorithmSuiteId, Long frameLength) throws EsdkClientException {
        try {
            AwsCrypto crypto = buildCrypto(algorithmSuiteId, frameLength);
            // Use the READ-side encrypting stream (source InputStream -> CryptoInputStream
            // producing ciphertext) rather than the write-side CryptoOutputStream. The
            // write-side form in ESDK Java 3.0.2 emits a malformed message for zero-byte
            // input (it never finalizes a valid header), which breaks the empty-plaintext
            // stream round trip (Requirement 4.9); the read-side form finalizes correctly
            // for all inputs including empty. Both drive the real ESDK streaming encrypt
            // API (Requirement 4.5).
            try (CryptoInputStream<?> encrypting = legacyCmm != null
                     ? crypto.createEncryptingStream(legacyCmm, plaintext, nonNull(encryptionContext))
                     : crypto.createEncryptingStream(cmm, plaintext, nonNull(encryptionContext))) {
                encrypting.transferTo(ciphertext);
            }
        } catch (Exception esdkFailure) {
            throw new EsdkClientException(esdkFailure);
        }
    }

    @Override
    public void decryptStream(InputStream ciphertext, OutputStream plaintext,
                              Map<String, String> encryptionContext) throws EsdkClientException {
        try {
            AwsCrypto crypto = buildCrypto(null, null);
            Map<String, String> ec = nonNull(encryptionContext);
            // Supply the reproduced encryption context on decrypt when present, so a
            // Required-Encryption-Context CMM (which drops the required keys from the
            // message header) can reconstruct them — mirroring the blob decrypt path.
            // Both drive the real ESDK streaming decrypt API (Requirement 4.6).
            if (legacyCmm != null) {
                requireNoReproducedContext(ec);
            }
            try (CryptoInputStream<?> decrypting = legacyCmm != null
                     ? crypto.createDecryptingStream(legacyCmm, ciphertext)
                     : ec.isEmpty()
                         ? crypto.createDecryptingStream(cmm, ciphertext)
                         : crypto.createDecryptingStream(cmm, ciphertext, ec)) {
                decrypting.transferTo(plaintext);
            }
        } catch (Exception esdkFailure) {
            throw new EsdkClientException(esdkFailure);
        }
    }

    @Override
    public boolean isStreamingCapable() {
        return true;
    }

    /**
     * Build an {@link AwsCrypto} for a single call, applying the client's fixed
     * commitment policy and optional max-EDK cap plus any per-request algorithm
     * suite / frame length overrides.
     */
    private AwsCrypto buildCrypto(String algorithmSuiteId, Long frameLength) {
        AwsCrypto.Builder builder = AwsCrypto.builder().withCommitmentPolicy(commitmentPolicy);
        if (maxEncryptedDataKeys != null) {
            builder.withMaxEncryptedDataKeys(maxEncryptedDataKeys);
        }
        if (algorithmSuiteId != null) {
            // The modeled ESDKAlgorithmSuiteId enum values match the ESDK
            // CryptoAlgorithm constant names one-for-one.
            builder.withEncryptionAlgorithm(CryptoAlgorithm.valueOf(algorithmSuiteId));
        }
        if (frameLength != null) {
            builder.withEncryptionFrameSize(Math.toIntExact(frameLength));
        }
        return builder.build();
    }

    /** The ESDK's own CMMs take no reproduced encryption context on decrypt. */
    private static void requireNoReproducedContext(Map<String, String> encryptionContext) {
        if (!encryptionContext.isEmpty()) {
            throw new UnsupportedOperationException(
                "a reproduced encryption context is not supported with the Caching CMM");
        }
    }

    private static Map<String, String> nonNull(Map<String, String> encryptionContext) {
        return encryptionContext == null ? Collections.emptyMap() : encryptionContext;
    }
}

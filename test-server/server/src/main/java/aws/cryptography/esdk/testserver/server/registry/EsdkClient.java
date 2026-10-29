package aws.cryptography.esdk.testserver.server.registry;

import aws.cryptography.esdk.testserver.server.error.EsdkClientException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;

/**
 * A single configured, language-specific ESDK client stored in the
 * {@link ClientRegistry}. On the Java server this is backed by the REAL AWS
 * Encryption SDK for Java (see {@code RealEsdkClient}); tests may substitute a
 * controllable fake to exercise the handler and error-mapping logic without real
 * crypto.
 *
 * <p>Every method that reaches the underlying ESDK declares
 * {@link EsdkClientException}: implementations catch exceptions thrown by the
 * real ESDK and rethrow them wrapped, so the operation wrapper can forward them
 * as an {@code ESDKClientError} with the ESDK message unmodified (Requirements
 * 4.10, 5.6, Property 8).
 */
public interface EsdkClient {

    /**
     * Encrypt an in-memory plaintext blob (Blob_Variant, Requirement 4.2).
     *
     * @param plaintext the plaintext bytes.
     * @param encryptionContext optional additional authenticated data; may be
     *     empty but not {@code null}.
     * @param algorithmSuiteId optional algorithm-suite override (enum value), or
     *     {@code null} for the client default.
     * @param frameLength optional framing length in bytes, or {@code null}.
     * @return the ciphertext bytes.
     * @throws EsdkClientException if the ESDK client fails (Requirement 4.10).
     */
    byte[] encrypt(byte[] plaintext, Map<String, String> encryptionContext,
                   String algorithmSuiteId, Long frameLength) throws EsdkClientException;

    /**
     * Decrypt an in-memory ciphertext blob (Blob_Variant, Requirement 4.3).
     *
     * @param ciphertext the ciphertext bytes.
     * @param encryptionContext optional encryption context to require on decrypt;
     *     may be empty but not {@code null}.
     * @return the plaintext bytes.
     * @throws EsdkClientException if the ESDK client fails (Requirement 4.10).
     */
    byte[] decrypt(byte[] ciphertext, Map<String, String> encryptionContext)
        throws EsdkClientException;

    /**
     * Encrypt a plaintext stream into a ciphertext stream (Stream_Variant,
     * Requirement 4.5). Only meaningful when {@link #isStreamingCapable()}.
     *
     * @throws EsdkClientException if the ESDK client fails (Requirement 4.10).
     */
    void encryptStream(InputStream plaintext, OutputStream ciphertext,
                       Map<String, String> encryptionContext,
                       String algorithmSuiteId, Long frameLength) throws EsdkClientException;

    /**
     * Decrypt a ciphertext stream into a plaintext stream (Stream_Variant,
     * Requirement 4.6). Only meaningful when {@link #isStreamingCapable()}.
     *
     * @throws EsdkClientException if the ESDK client fails (Requirement 4.10).
     */
    void decryptStream(InputStream ciphertext, OutputStream plaintext,
                       Map<String, String> encryptionContext) throws EsdkClientException;

    /**
     * @return whether the backing ESDK implementation supports the Stream_Variant.
     *     The Java ESDK is Streaming_Capable, so {@code RealEsdkClient} returns
     *     {@code true} (Requirement 4.5, 4.6).
     */
    boolean isStreamingCapable();
}

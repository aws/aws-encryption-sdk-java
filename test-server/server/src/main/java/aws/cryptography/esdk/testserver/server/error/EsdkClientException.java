package aws.cryptography.esdk.testserver.server.error;

/**
 * Marks a failure that originated as an exception thrown by the underlying real
 * ESDK client (encrypt/decrypt, or config-driven keyring/CMM construction that
 * the ESDK itself rejects). The {@link aws.cryptography.esdk.testserver.server.registry.EsdkClient}
 * implementation catches the ESDK exception and rethrows it wrapped in this type
 * so the {@link ErrorClassifier} can distinguish ESDK-origin failures from
 * TestServer-framework failures (Requirements 5.5, 5.6, Property 8).
 *
 * <p>The ESDK exception's message is captured verbatim so the classifier can
 * forward it unmodified in an {@code ESDKClientError} (Requirement 5.6).
 */
public final class EsdkClientException extends Exception {

    /**
     * Wrap an ESDK-thrown exception.
     *
     * @param cause the exception thrown by the real ESDK client; its message is
     *     forwarded unmodified.
     */
    public EsdkClientException(Throwable cause) {
        super(cause == null ? null : cause.getMessage(), cause);
    }

    /**
     * @return the ESDK exception's message, unmodified (Requirement 5.6). May be
     *     {@code null} if the underlying ESDK exception carried no message.
     */
    public String esdkMessage() {
        return getMessage();
    }
}

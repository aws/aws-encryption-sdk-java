package aws.cryptography.esdk.testserver.server.handler;

import aws.cryptography.esdk.testserver.server.error.EsdkClientException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A controllable {@link aws.cryptography.esdk.testserver.server.registry.EsdkClient}
 * fake used by the handler and error-mapping property tests. It can be told to
 * succeed (echoing bytes) or to fail on demand, either as an ESDK-origin failure
 * (a wrapped {@link EsdkClientException}) or a framework-origin failure (a raw
 * unchecked exception). It counts crypto invocations so tests can assert that a
 * rejected request performed no ESDK operation (Property 5).
 */
final class ControllableEsdkClient implements aws.cryptography.esdk.testserver.server.registry.EsdkClient {

    enum Mode { SUCCEED, FAIL_ESDK, FAIL_FRAMEWORK }

    private final Mode mode;
    private final String failureMessage;
    private final AtomicInteger cryptoCalls = new AtomicInteger();

    private ControllableEsdkClient(Mode mode, String failureMessage) {
        this.mode = mode;
        this.failureMessage = failureMessage;
    }

    static ControllableEsdkClient succeeding() {
        return new ControllableEsdkClient(Mode.SUCCEED, null);
    }

    static ControllableEsdkClient failingInsideEsdk(String message) {
        return new ControllableEsdkClient(Mode.FAIL_ESDK, message);
    }

    static ControllableEsdkClient failingInFramework(String message) {
        return new ControllableEsdkClient(Mode.FAIL_FRAMEWORK, message);
    }

    int cryptoCalls() {
        return cryptoCalls.get();
    }

    private byte[] act(byte[] payload) throws EsdkClientException {
        cryptoCalls.incrementAndGet();
        switch (mode) {
            case SUCCEED:
                return payload;
            case FAIL_ESDK:
                throw new EsdkClientException(new RuntimeException(failureMessage));
            case FAIL_FRAMEWORK:
            default:
                throw new IllegalStateException(failureMessage);
        }
    }

    @Override
    public byte[] encrypt(byte[] plaintext, Map<String, String> encryptionContext,
                          String algorithmSuiteId, Long frameLength) throws EsdkClientException {
        return act(plaintext);
    }

    @Override
    public byte[] decrypt(byte[] ciphertext, Map<String, String> encryptionContext)
        throws EsdkClientException {
        return act(ciphertext);
    }

    @Override
    public void encryptStream(InputStream plaintext, OutputStream ciphertext,
                              Map<String, String> encryptionContext,
                              String algorithmSuiteId, Long frameLength) throws EsdkClientException {
        act(new byte[0]);
    }

    @Override
    public void decryptStream(InputStream ciphertext, OutputStream plaintext,
                              Map<String, String> encryptionContext) throws EsdkClientException {
        act(new byte[0]);
    }

    @Override
    public boolean isStreamingCapable() {
        return true;
    }
}

package aws.cryptography.esdk.testserver.server.handler;

import aws.cryptography.esdk.testserver.server.error.OperationWrapper;
import aws.cryptography.esdk.testserver.server.model.ESDKAlgorithmSuiteId;
import aws.cryptography.esdk.testserver.server.model.EncryptInput;
import aws.cryptography.esdk.testserver.server.model.EncryptOutput;
import aws.cryptography.esdk.testserver.server.registry.EsdkClient;
import aws.cryptography.esdk.testserver.server.service.EncryptOperation;
import java.nio.ByteBuffer;
import software.amazon.smithy.java.server.RequestContext;

/**
 * Blob variant of encrypt: resolves the {@code ClientId}, encrypts the plaintext
 * blob with the referenced real ESDK client, and returns the ciphertext blob
 * (Requirement 4.2). A failure inside the ESDK is forwarded as an
 * {@code ESDKClientError} with no ciphertext and an unchanged registry
 * (Requirements 4.10, Property 8); a missing/unknown {@code ClientId} yields a
 * {@code GenericServerError} before any ESDK call (Requirement 3.9).
 */
public final class EncryptHandler implements EncryptOperation {

    private final ClientIdGuard guard;
    private final OperationWrapper wrapper;

    public EncryptHandler(ClientIdGuard guard, OperationWrapper wrapper) {
        this.guard = guard;
        this.wrapper = wrapper;
    }

    @Override
    public EncryptOutput encrypt(EncryptInput input, RequestContext context) {
        return wrapper.invoke("Encrypt", () -> {
            EsdkClient client = guard.resolve(input.getClientId());
            ESDKAlgorithmSuiteId suite = input.getAlgorithmSuiteId();
            byte[] ciphertext = client.encrypt(
                Blobs.toArray(input.getPlaintext()),
                input.getEncryptionContext(),
                suite == null ? null : suite.getValue(),
                input.getFrameLength());
            return EncryptOutput.builder().ciphertext(ByteBuffer.wrap(ciphertext)).build();
        });
    }
}

package aws.cryptography.esdk.testserver.server.handler;

import aws.cryptography.esdk.testserver.server.error.OperationWrapper;
import aws.cryptography.esdk.testserver.server.model.DecryptInput;
import aws.cryptography.esdk.testserver.server.model.DecryptOutput;
import aws.cryptography.esdk.testserver.server.registry.EsdkClient;
import aws.cryptography.esdk.testserver.server.service.DecryptOperation;
import java.nio.ByteBuffer;
import software.amazon.smithy.java.server.RequestContext;

/**
 * Blob variant of decrypt: resolves the {@code ClientId}, decrypts the ciphertext
 * blob with the referenced real ESDK client, and returns the plaintext blob
 * (Requirement 4.3). A failure inside the ESDK is forwarded as an
 * {@code ESDKClientError} with no plaintext and an unchanged registry
 * (Requirements 4.10, Property 8); a missing/unknown {@code ClientId} yields a
 * {@code GenericServerError} before any ESDK call (Requirement 3.9).
 */
public final class DecryptHandler implements DecryptOperation {

    private final ClientIdGuard guard;
    private final OperationWrapper wrapper;

    public DecryptHandler(ClientIdGuard guard, OperationWrapper wrapper) {
        this.guard = guard;
        this.wrapper = wrapper;
    }

    @Override
    public DecryptOutput decrypt(DecryptInput input, RequestContext context) {
        return wrapper.invoke("Decrypt", () -> {
            EsdkClient client = guard.resolve(input.getClientId());
            byte[] plaintext = client.decrypt(
                Blobs.toArray(input.getCiphertext()),
                input.getEncryptionContext());
            return DecryptOutput.builder().plaintext(ByteBuffer.wrap(plaintext)).build();
        });
    }
}

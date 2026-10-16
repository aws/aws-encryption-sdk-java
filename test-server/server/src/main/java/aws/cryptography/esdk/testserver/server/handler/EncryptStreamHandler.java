package aws.cryptography.esdk.testserver.server.handler;

import aws.cryptography.esdk.testserver.server.error.OperationWrapper;
import aws.cryptography.esdk.testserver.server.model.ESDKAlgorithmSuiteId;
import aws.cryptography.esdk.testserver.server.model.EncryptStreamInput;
import aws.cryptography.esdk.testserver.server.model.EncryptStreamOutput;
import aws.cryptography.esdk.testserver.server.registry.EsdkClient;
import aws.cryptography.esdk.testserver.server.service.EncryptStreamOperation;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import software.amazon.smithy.java.server.RequestContext;

/**
 * Stream variant of encrypt for the Streaming_Capable Java server (Requirement
 * 4.5). The plaintext payload rides on the wire as a plain {@code Blob} (not a
 * Smithy {@code @streaming} member, because stock smithy-java 1.4.0 does not
 * transmit {@code @streaming} members over rpcv2-CBOR); the streaming semantics
 * live entirely server-side. This handler resolves the {@code ClientId}, wraps
 * the received plaintext bytes in an {@link InputStream}, drives the REAL ESDK
 * Java streaming encrypt API, collects the streamed ciphertext into a blob, and
 * returns it (Requirements 4.1, 4.5). ESDK failures forward as an
 * {@code ESDKClientError} with the ESDK message unmodified (Requirement 4.11);
 * a missing/unknown {@code ClientId} yields a {@code GenericServerError} before
 * any ESDK call (Requirement 3.9).
 */
public final class EncryptStreamHandler implements EncryptStreamOperation {

    private final ClientIdGuard guard;
    private final OperationWrapper wrapper;

    public EncryptStreamHandler(ClientIdGuard guard, OperationWrapper wrapper) {
        this.guard = guard;
        this.wrapper = wrapper;
    }

    @Override
    public EncryptStreamOutput encryptStream(EncryptStreamInput input, RequestContext context) {
        return wrapper.invoke("EncryptStream", () -> {
            EsdkClient client = guard.resolve(input.getClientId());
            ESDKAlgorithmSuiteId suite = input.getAlgorithmSuiteId();
            // Drive the ESDK STREAMING API even though the payload rides as a blob:
            // wrap the received bytes in a stream, stream-encrypt, collect the bytes.
            ByteArrayOutputStream ciphertext = new ByteArrayOutputStream();
            try (InputStream plaintext =
                     new ByteArrayInputStream(Blobs.toArray(input.getPlaintext()))) {
                client.encryptStream(
                    plaintext,
                    ciphertext,
                    input.getEncryptionContext(),
                    suite == null ? null : suite.getValue(),
                    input.getFrameLength());
            }
            return EncryptStreamOutput.builder()
                .ciphertext(ByteBuffer.wrap(ciphertext.toByteArray()))
                .build();
        });
    }
}

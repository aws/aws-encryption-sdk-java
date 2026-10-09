package aws.cryptography.esdk.testserver.server.handler;

import aws.cryptography.esdk.testserver.server.error.OperationWrapper;
import aws.cryptography.esdk.testserver.server.model.DecryptStreamInput;
import aws.cryptography.esdk.testserver.server.model.DecryptStreamOutput;
import aws.cryptography.esdk.testserver.server.registry.EsdkClient;
import aws.cryptography.esdk.testserver.server.service.DecryptStreamOperation;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import software.amazon.smithy.java.server.RequestContext;

/**
 * Stream variant of decrypt for the Streaming_Capable Java server (Requirement
 * 4.6). The ciphertext payload rides on the wire as a plain {@code Blob} (not a
 * Smithy {@code @streaming} member, because stock smithy-java 1.4.0 does not
 * transmit {@code @streaming} members over rpcv2-CBOR); the streaming semantics
 * live entirely server-side. This handler resolves the {@code ClientId}, wraps
 * the received ciphertext bytes in an {@link InputStream}, drives the REAL ESDK
 * Java streaming decrypt API, collects the streamed plaintext into a blob, and
 * returns it (Requirements 4.1, 4.6). ESDK failures forward as an
 * {@code ESDKClientError} with the ESDK message unmodified (Requirement 4.11);
 * a missing/unknown {@code ClientId} yields a {@code GenericServerError} before
 * any ESDK call (Requirement 3.9).
 */
public final class DecryptStreamHandler implements DecryptStreamOperation {

    private final ClientIdGuard guard;
    private final OperationWrapper wrapper;

    public DecryptStreamHandler(ClientIdGuard guard, OperationWrapper wrapper) {
        this.guard = guard;
        this.wrapper = wrapper;
    }

    @Override
    public DecryptStreamOutput decryptStream(DecryptStreamInput input, RequestContext context) {
        return wrapper.invoke("DecryptStream", () -> {
            EsdkClient client = guard.resolve(input.getClientId());
            // Drive the ESDK STREAMING API even though the payload rides as a blob:
            // wrap the received bytes in a stream, stream-decrypt, collect the bytes.
            ByteArrayOutputStream plaintext = new ByteArrayOutputStream();
            try (InputStream ciphertext =
                     new ByteArrayInputStream(Blobs.toArray(input.getCiphertext()))) {
                client.decryptStream(ciphertext, plaintext, input.getEncryptionContext());
            }
            return DecryptStreamOutput.builder()
                .plaintext(ByteBuffer.wrap(plaintext.toByteArray()))
                .build();
        });
    }
}

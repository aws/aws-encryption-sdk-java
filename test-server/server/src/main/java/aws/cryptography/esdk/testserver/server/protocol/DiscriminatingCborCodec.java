package aws.cryptography.esdk.testserver.server.protocol;

import java.io.OutputStream;
import java.nio.ByteBuffer;
import software.amazon.smithy.java.cbor.Rpcv2CborCodec;
import software.amazon.smithy.java.core.serde.Codec;
import software.amazon.smithy.java.core.serde.ShapeDeserializer;
import software.amazon.smithy.java.core.serde.ShapeSerializer;

/**
 * A {@link Codec} that behaves exactly like the stock rpcv2Cbor codec for
 * deserialization and for non-error serialization, but wraps the serializer so
 * that modeled error structs are emitted as discriminated documents carrying a
 * {@code __type} field (see {@link DiscriminatingCborSerializer} for the why).
 *
 * <p>This is the single, surgical change that makes the two modeled errors
 * transmit distinctly over rpcv2Cbor without touching the generated client, the
 * model, or the blob/normal-response wire form.
 */
public final class DiscriminatingCborCodec implements Codec {

    private final Codec delegate = Rpcv2CborCodec.builder().build();

    @Override
    public ShapeSerializer createSerializer(OutputStream sink) {
        return new DiscriminatingCborSerializer(delegate.createSerializer(sink));
    }

    @Override
    public ShapeDeserializer createDeserializer(byte[] source) {
        return delegate.createDeserializer(source);
    }

    @Override
    public ShapeDeserializer createDeserializer(ByteBuffer source) {
        return delegate.createDeserializer(source);
    }

    @Override
    public void close() {
        delegate.close();
    }
}

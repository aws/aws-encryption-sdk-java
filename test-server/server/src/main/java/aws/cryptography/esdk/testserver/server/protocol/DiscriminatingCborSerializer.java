package aws.cryptography.esdk.testserver.server.protocol;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.function.BiConsumer;
import software.amazon.smithy.java.core.error.ModeledException;
import software.amazon.smithy.java.core.schema.Schema;
import software.amazon.smithy.java.core.schema.SerializableStruct;
import software.amazon.smithy.java.core.serde.MapSerializer;
import software.amazon.smithy.java.core.serde.ShapeSerializer;
import software.amazon.smithy.java.core.serde.document.Document;
import software.amazon.smithy.java.core.serde.event.EventStream;
import software.amazon.smithy.java.io.datastream.DataStream;

/**
 * A {@link ShapeSerializer} that delegates everything to the stock rpcv2Cbor CBOR
 * serializer, EXCEPT that a modeled error struct is serialized as a
 * <em>discriminated {@link Document}</em> rather than a plain struct.
 *
 * <p>Why: stock smithy-java 1.4.0 serializes a modeled error over rpcv2Cbor as a
 * bare map of its members ({@code {"message": ...}}) with no {@code __type}
 * discriminator. The generated Java {@code Test_Client}'s error deserializer keys
 * off {@code __type} to reconstruct the specific modeled error shape; without it
 * both {@code GenericServerError} and {@code ESDKClientError} come back as a
 * generic {@code CallException} and are indistinguishable end-to-end (the
 * smithy-java rpcv2-CBOR modeled-error transmission caveat called out in the
 * design's Error Handling section).
 *
 * <p>Serializing the error as {@code Document.of(struct)} makes the CBOR document
 * path emit the {@code __type} discriminator (the error's shape id) alongside the
 * members, so the stock client maps the response back to the correct modeled
 * error type. Non-error structs (normal operation outputs) are serialized exactly
 * as before, so the blob round-trip wire form is byte-identical to stock.
 */
final class DiscriminatingCborSerializer implements ShapeSerializer {

    private final ShapeSerializer delegate;

    DiscriminatingCborSerializer(ShapeSerializer delegate) {
        this.delegate = delegate;
    }

    @Override
    public void writeStruct(Schema schema, SerializableStruct struct) {
        if (struct instanceof ModeledException) {
            // Serialize as a discriminated document so the CBOR document path emits
            // the __type discriminator the client needs to pick the modeled error.
            Document.of(struct).serialize(delegate);
        } else {
            delegate.writeStruct(schema, struct);
        }
    }

    // ---- everything else delegates unchanged -------------------------------

    @Override
    public <T> void writeList(Schema schema, T state, int size,
                              BiConsumer<T, ShapeSerializer> consumer) {
        delegate.writeList(schema, state, size, consumer);
    }

    @Override
    public <T> void writeMap(Schema schema, T state, int size,
                             BiConsumer<T, MapSerializer> consumer) {
        delegate.writeMap(schema, state, size, consumer);
    }

    @Override
    public void writeBoolean(Schema schema, boolean value) {
        delegate.writeBoolean(schema, value);
    }

    @Override
    public void writeByte(Schema schema, byte value) {
        delegate.writeByte(schema, value);
    }

    @Override
    public void writeShort(Schema schema, short value) {
        delegate.writeShort(schema, value);
    }

    @Override
    public void writeInteger(Schema schema, int value) {
        delegate.writeInteger(schema, value);
    }

    @Override
    public void writeLong(Schema schema, long value) {
        delegate.writeLong(schema, value);
    }

    @Override
    public void writeFloat(Schema schema, float value) {
        delegate.writeFloat(schema, value);
    }

    @Override
    public void writeDouble(Schema schema, double value) {
        delegate.writeDouble(schema, value);
    }

    @Override
    public void writeBigInteger(Schema schema, BigInteger value) {
        delegate.writeBigInteger(schema, value);
    }

    @Override
    public void writeBigDecimal(Schema schema, BigDecimal value) {
        delegate.writeBigDecimal(schema, value);
    }

    @Override
    public void writeString(Schema schema, String value) {
        delegate.writeString(schema, value);
    }

    @Override
    public void writeBlob(Schema schema, ByteBuffer value) {
        delegate.writeBlob(schema, value);
    }

    @Override
    public void writeBlob(Schema schema, byte[] value) {
        delegate.writeBlob(schema, value);
    }

    @Override
    public void writeDataStream(Schema schema, DataStream value) {
        delegate.writeDataStream(schema, value);
    }

    @Override
    public void writeEventStream(Schema schema,
                                 EventStream<? extends SerializableStruct> value) {
        delegate.writeEventStream(schema, value);
    }

    @Override
    public void writeTimestamp(Schema schema, Instant value) {
        delegate.writeTimestamp(schema, value);
    }

    @Override
    public void writeDocument(Schema schema, Document value) {
        delegate.writeDocument(schema, value);
    }

    @Override
    public void writeNull(Schema schema) {
        delegate.writeNull(schema);
    }

    @Override
    public void flush() {
        delegate.flush();
    }

    @Override
    public void close() {
        delegate.close();
    }
}

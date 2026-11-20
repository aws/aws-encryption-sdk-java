package aws.cryptography.esdk.testserver.server.config;

import aws.cryptography.esdk.testserver.server.model.CryptographicMaterialsManager;
import aws.cryptography.esdk.testserver.server.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.server.model.Keyring;
import java.nio.ByteBuffer;
import software.amazon.smithy.java.cbor.Rpcv2CborCodec;
import software.amazon.smithy.java.core.schema.SerializableStruct;
import software.amazon.smithy.java.core.schema.ShapeBuilder;
import software.amazon.smithy.java.core.serde.Codec;

/**
 * Marshals and unmarshals the tagged-union config shapes through the exact wire
 * form used by the service protocol, rpcv2Cbor (Requirement 2.2). Because the
 * config shapes reference themselves recursively — a Caching or
 * RequiredEncryptionContext CMM wraps another CMM, and a Multi keyring contains
 * child keyrings — marshalling round-trips at any nesting depth
 * (Requirement 2.5).
 *
 * <p>The generated shapes already know how to (de)serialize themselves via
 * smithy-java's serde; this class pins that to the rpcv2Cbor codec so what is
 * marshalled here is byte-identical to what crosses the wire, and exposes small
 * typed round-trip helpers used by the handlers and property tests.
 */
public final class ConfigMarshaller {

    private final Codec codec;

    public ConfigMarshaller() {
        this.codec = Rpcv2CborCodec.builder().build();
    }

    /** Marshal any config struct to its rpcv2Cbor wire bytes. */
    public byte[] marshal(SerializableStruct config) {
        ByteBuffer buffer = codec.serialize(config);
        byte[] bytes = new byte[buffer.remaining()];
        buffer.get(bytes);
        return bytes;
    }

    /** Unmarshal wire bytes back into a config struct using the given builder. */
    public <T extends SerializableStruct> T unmarshal(byte[] wire, ShapeBuilder<T> builder) {
        return codec.deserializeShape(wire, builder);
    }

    /** Round-trip a whole client config through the wire form. */
    public ESDKClientConfig roundTrip(ESDKClientConfig config) {
        return unmarshal(marshal(config), ESDKClientConfig.builder());
    }

    /** Round-trip a CMM (possibly deeply nested) through the wire form. */
    public CryptographicMaterialsManager roundTrip(CryptographicMaterialsManager cmm) {
        return unmarshal(marshal(cmm), CryptographicMaterialsManager.builder());
    }

    /** Round-trip a keyring (possibly deeply nested) through the wire form. */
    public Keyring roundTrip(Keyring keyring) {
        return unmarshal(marshal(keyring), Keyring.builder());
    }
}

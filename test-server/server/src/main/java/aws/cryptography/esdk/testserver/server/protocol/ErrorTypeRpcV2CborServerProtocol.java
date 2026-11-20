package aws.cryptography.esdk.testserver.server.protocol;

import java.util.List;
import software.amazon.smithy.java.core.serde.Codec;
import software.amazon.smithy.java.server.Service;
import software.amazon.smithy.java.server.rpcv2.AbstractRpcV2ServerProtocol;
import software.amazon.smithy.model.shapes.ShapeId;

/**
 * A drop-in rpcv2Cbor server protocol identical to the stock one except that its
 * codec emits the {@code __type} discriminator on modeled errors
 * ({@link DiscriminatingCborCodec}), so {@code GenericServerError} and
 * {@code ESDKClientError} transmit and stay distinguishable through the stock
 * generated Java {@code Test_Client} (Requirements 3.9, 4.11, 5.5, 5.6, 6.1–6.4).
 *
 * <p>It parses and dispatches the same {@code /service/{Service}/operation/{Op}}
 * rpcv2 requests as the stock protocol (path-based resolution, inherited from
 * {@link AbstractRpcV2ServerProtocol}) and decodes input with the same CBOR codec,
 * so the blob round-trip and every non-error response are byte-identical to stock.
 * Only the error response body gains the {@code __type} field.
 *
 * <p>It advertises a <em>distinct</em> protocol id (not
 * {@code smithy.protocols#rpcv2Cbor}) so it coexists with the stock provider in
 * the framework's {@code ShapeId}-keyed provider map without a duplicate-key
 * clash; the accompanying provider ranks ahead of the stock one so this protocol
 * is selected for the rpcv2 requests the service receives.
 */
public final class ErrorTypeRpcV2CborServerProtocol extends AbstractRpcV2ServerProtocol {

    /**
     * A distinct protocol id (must not equal {@code smithy.protocols#rpcv2Cbor},
     * which is the stock provider's key). The wire behavior remains rpcv2Cbor.
     */
    static final ShapeId PROTOCOL_ID =
        ShapeId.from("aws.cryptography.esdk.testserver#rpcV2CborWithErrorType");

    private final Codec codec = new DiscriminatingCborCodec();

    ErrorTypeRpcV2CborServerProtocol(List<Service> services) {
        super(services, "application/cbor", true);
    }

    @Override
    public ShapeId getProtocolId() {
        return PROTOCOL_ID;
    }

    @Override
    protected Codec codec() {
        return codec;
    }
}

package aws.cryptography.esdk.testserver.server.protocol;

import java.util.List;
import software.amazon.smithy.java.server.Service;
import software.amazon.smithy.java.server.core.ServerProtocol;
import software.amazon.smithy.java.server.core.ServerProtocolProvider;
import software.amazon.smithy.model.shapes.ShapeId;

/**
 * SPI provider for {@link ErrorTypeRpcV2CborServerProtocol}. Registered via
 * {@code META-INF/services/software.amazon.smithy.java.server.core.ServerProtocolProvider}.
 *
 * <p>It advertises a distinct {@link #getProtocolId() protocol id} so it does not
 * collide with the stock rpcv2Cbor provider in the framework's {@code ShapeId}-keyed
 * provider map (which would throw on a duplicate key). The framework sorts protocol
 * providers by {@link #precision()} ascending and dispatches each request to the
 * first protocol that resolves it; returning a precision lower than the stock
 * provider's ({@code 0}) makes this protocol win for the rpcv2 requests the service
 * receives, so the {@code __type}-emitting error serialization is what clients see.
 */
public final class ErrorTypeRpcV2CborServerProtocolProvider implements ServerProtocolProvider {

    @Override
    public ServerProtocol provideProtocolHandler(List<Service> services) {
        return new ErrorTypeRpcV2CborServerProtocol(services);
    }

    @Override
    public ShapeId getProtocolId() {
        return ErrorTypeRpcV2CborServerProtocol.PROTOCOL_ID;
    }

    @Override
    public int precision() {
        // Sorted ascending; lower is tried first. Beat the stock provider (0) so
        // this __type-emitting protocol handles the service's rpcv2 requests.
        return -100;
    }
}

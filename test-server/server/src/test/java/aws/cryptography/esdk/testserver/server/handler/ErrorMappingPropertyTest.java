package aws.cryptography.esdk.testserver.server.handler;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.fail;

import aws.cryptography.esdk.testserver.server.error.OperationWrapper;
import aws.cryptography.esdk.testserver.server.model.DecryptInput;
import aws.cryptography.esdk.testserver.server.model.ESDKClientError;
import aws.cryptography.esdk.testserver.server.model.EncryptInput;
import aws.cryptography.esdk.testserver.server.model.GenericServerError;
import aws.cryptography.esdk.testserver.server.registry.ClientRegistry;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.GenerationMode;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

/**
 * Property-based test for error mapping by origin at the handler layer, using
 * jqwik. Runs a minimum of 100 generated iterations.
 */
class ErrorMappingPropertyTest {

    private enum Op { ENCRYPT, DECRYPT }

    // Feature: esdk-test-server, Property 8: Errors are mapped by origin
    @Property(tries = 200, generation = GenerationMode.RANDOMIZED)
    void errorsAreMappedByOrigin(@ForAll("ops") Op op,
                                 @ForAll boolean esdkOrigin,
                                 @ForAll("messages") String message) {
        ClientRegistry registry = new ClientRegistry();
        OperationWrapper wrapper = new OperationWrapper();
        ClientIdGuard guard = new ClientIdGuard(registry);

        ControllableEsdkClient client = esdkOrigin
            ? ControllableEsdkClient.failingInsideEsdk(message)
            : ControllableEsdkClient.failingInFramework(message);
        String clientId = registry.register(client);
        int sizeBefore = registry.size();

        Throwable thrown = runExpectingThrow(op, guard, wrapper, clientId);

        if (esdkOrigin) {
            // (5.6, P8) ESDK-origin failure -> ESDKClientError, message unmodified,
            // never a GenericServerError.
            ESDKClientError error = assertInstanceOf(ESDKClientError.class, thrown,
                "an ESDK-origin failure must map to ESDKClientError");
            assertEquals(message, error.getMessage(),
                "ESDKClientError message must equal the ESDK exception message, unmodified");
        } else {
            // (5.5, P8) framework-origin failure -> GenericServerError, never an
            // ESDKClientError.
            assertInstanceOf(GenericServerError.class, thrown,
                "a framework-origin failure must map to GenericServerError");
        }

        // In the failure case no ciphertext/plaintext is returned (an exception
        // was thrown, not an output) and the registry is unchanged.
        assertEquals(sizeBefore, registry.size(),
            "a failed operation must leave the registry unchanged");
    }

    private static Throwable runExpectingThrow(Op op, ClientIdGuard guard,
                                               OperationWrapper wrapper, String clientId) {
        try {
            switch (op) {
                case ENCRYPT -> new EncryptHandler(guard, wrapper).encrypt(
                    EncryptInput.builder()
                        .clientId(clientId)
                        .plaintext(ByteBuffer.wrap("payload".getBytes(StandardCharsets.UTF_8)))
                        .build(),
                    null);
                case DECRYPT -> new DecryptHandler(guard, wrapper).decrypt(
                    DecryptInput.builder()
                        .clientId(clientId)
                        .ciphertext(ByteBuffer.wrap("payload".getBytes(StandardCharsets.UTF_8)))
                        .build(),
                    null);
                default -> fail("unhandled op");
            }
        } catch (Throwable t) {
            return t;
        }
        throw new AssertionError("expected the operation to throw a modeled error");
    }

    @Provide
    Arbitrary<Op> ops() {
        return Arbitraries.of(Op.class);
    }

    @Provide
    Arbitrary<String> messages() {
        return Arbitraries.strings().ofMinLength(1).ofMaxLength(120);
    }
}

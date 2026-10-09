package aws.cryptography.esdk.testserver.server.error;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.fail;

import aws.cryptography.esdk.testserver.server.model.ESDKClientError;
import aws.cryptography.esdk.testserver.server.model.GenericServerError;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.GenerationMode;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

/**
 * Property-based test for the catch-all operation wrapper, using jqwik. Runs a
 * minimum of 100 generated iterations.
 */
class OperationWrapperPropertyTest {

    private final OperationWrapper wrapper = new OperationWrapper();

    /** The kind of outcome a handler body produces. */
    private enum Outcome { SUCCESS, THROW_GENERIC, THROW_ESDK_MODELED, THROW_ESDK_WRAPPED, THROW_NON_MODELED }

    // Feature: esdk-test-server, Property 9: Every operation returns a modeled outcome with a non-empty message
    @Property(tries = 200, generation = GenerationMode.RANDOMIZED)
    void everyOperationYieldsAModeledOutcome(@ForAll("outcomes") Outcome outcome,
                                             @ForAll("messages") String message) {
        OperationWrapper.HandlerBody<String> body = bodyFor(outcome, message);

        switch (outcome) {
            case SUCCESS -> {
                // A successful handler returns its modeled response unchanged.
                String result = wrapper.invoke("Op", body);
                assertEquals(message, result, "success response must pass through unchanged");
            }
            case THROW_GENERIC -> {
                GenericServerError error = assertThrowsExactly(GenericServerError.class,
                    () -> wrapper.invoke("Op", body));
                // (6.1) modeled error preserved unchanged.
                assertEquals(message, error.getMessage(), "modeled message must be preserved");
                assertNonEmptyMessage(error.getMessage());
            }
            case THROW_ESDK_MODELED -> {
                ESDKClientError error = assertThrowsExactly(ESDKClientError.class,
                    () -> wrapper.invoke("Op", body));
                assertEquals(message, error.getMessage(), "modeled message must be preserved");
                assertNonEmptyMessage(error.getMessage());
            }
            case THROW_ESDK_WRAPPED -> {
                // (5.6) ESDK-origin failures become ESDKClientError, message unmodified.
                ESDKClientError error = assertThrowsExactly(ESDKClientError.class,
                    () -> wrapper.invoke("Op", body));
                assertEquals(message, error.getMessage(),
                    "ESDK exception message must be forwarded unmodified");
                assertNonEmptyMessage(error.getMessage());
            }
            case THROW_NON_MODELED -> {
                // (6.2) non-modeled exceptions become a GenericServerError whose
                // non-empty message includes the originating description.
                GenericServerError error = assertThrowsExactly(GenericServerError.class,
                    () -> wrapper.invoke("Op", body));
                assertNonEmptyMessage(error.getMessage());
                assertFalse(error.getMessage().isEmpty(), "message must include a description");
            }
            default -> fail("unhandled outcome");
        }
    }

    private static OperationWrapper.HandlerBody<String> bodyFor(Outcome outcome, String message) {
        return switch (outcome) {
            case SUCCESS -> () -> message;
            case THROW_GENERIC -> () -> {
                throw GenericServerError.builder().message(message).build();
            };
            case THROW_ESDK_MODELED -> () -> {
                throw ESDKClientError.builder().message(message).build();
            };
            case THROW_ESDK_WRAPPED -> () -> {
                throw new EsdkClientException(new RuntimeException(message));
            };
            case THROW_NON_MODELED -> () -> {
                throw new IllegalStateException(message);
            };
        };
    }

    private static void assertNonEmptyMessage(String message) {
        if (message == null || message.isEmpty()) {
            fail("every returned modeled error must carry a non-empty message");
        }
    }

    @FunctionalInterface
    private interface ThrowingCall {
        void run();
    }

    @SuppressWarnings("unchecked")
    private static <T extends Throwable> T assertThrowsExactly(Class<T> type, ThrowingCall call) {
        try {
            call.run();
        } catch (Throwable thrown) {
            if (type.isInstance(thrown)) {
                return (T) thrown;
            }
            throw new AssertionError("expected " + type.getSimpleName() + " but got "
                + thrown.getClass().getName(), thrown);
        }
        throw new AssertionError("expected " + type.getSimpleName() + " but nothing was thrown");
    }

    @Provide
    Arbitrary<Outcome> outcomes() {
        return Arbitraries.of(Outcome.class);
    }

    @Provide
    Arbitrary<String> messages() {
        // Non-empty messages: modeled-error message members are required and
        // non-empty, and ESDK exceptions carry a description.
        return Arbitraries.strings().ofMinLength(1).ofMaxLength(120);
    }
}

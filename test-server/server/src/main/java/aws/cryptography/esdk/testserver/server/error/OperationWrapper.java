package aws.cryptography.esdk.testserver.server.error;

/**
 * Catch-all wrapper applied to every operation handler so that each operation's
 * outcome is exactly one of: a successful modeled response, a
 * {@link aws.cryptography.esdk.testserver.server.model.GenericServerError}, or an
 * {@link aws.cryptography.esdk.testserver.server.model.ESDKClientError} — never a
 * bare HTTP error (Requirements 6.1, 6.2, 6.3, 6.4, Property 9).
 *
 * <p>The wrapper runs the handler body; if it returns normally that value is the
 * successful modeled response. If the body throws, the throwable is routed
 * through {@link ErrorClassifier} and the resulting modeled error is thrown so
 * the smithy-java runtime serializes it as one of the two declared error shapes.
 * Because the classifier always yields a modeled error, no non-modeled exception
 * can escape a wrapped handler.
 */
public final class OperationWrapper {

    private final ErrorClassifier classifier;

    public OperationWrapper() {
        this(new ErrorClassifier());
    }

    public OperationWrapper(ErrorClassifier classifier) {
        this.classifier = classifier;
    }

    /**
     * A handler body that produces the operation's successful modeled response,
     * or throws. Unlike {@link java.util.function.Supplier}, it may throw checked
     * exceptions (notably {@link EsdkClientException} from the real ESDK client).
     */
    @FunctionalInterface
    public interface HandlerBody<T> {
        T run() throws Exception;
    }

    /**
     * Run a handler body under the catch-all contract.
     *
     * @param operationName the operation name, used for framework-error messages.
     * @param body the handler body.
     * @param <T> the operation's output type.
     * @return the successful modeled response produced by {@code body}.
     * @throws aws.cryptography.esdk.testserver.server.model.GenericServerError or
     *     {@link aws.cryptography.esdk.testserver.server.model.ESDKClientError} if
     *     the body throws; the origin determines which (Property 8, 9).
     */
    public <T> T invoke(String operationName, HandlerBody<T> body) {
        try {
            return body.run();
        } catch (Throwable failure) {
            throw classifier.classify(operationName, failure);
        }
    }
}

package aws.cryptography.esdk.testserver.server.handler;

import aws.cryptography.esdk.testserver.server.model.AdvanceClockInput;
import aws.cryptography.esdk.testserver.server.model.AdvanceClockOutput;
import aws.cryptography.esdk.testserver.server.model.DecryptConcurrentlyInput;
import aws.cryptography.esdk.testserver.server.model.DecryptConcurrentlyOutput;
import aws.cryptography.esdk.testserver.server.model.EncryptConcurrentlyInput;
import aws.cryptography.esdk.testserver.server.model.EncryptConcurrentlyOutput;
import aws.cryptography.esdk.testserver.server.model.GenericServerError;
import aws.cryptography.esdk.testserver.server.model.GetCallCountsInput;
import aws.cryptography.esdk.testserver.server.model.GetCallCountsOutput;
import aws.cryptography.esdk.testserver.server.service.AdvanceClockOperation;
import aws.cryptography.esdk.testserver.server.service.DecryptConcurrentlyOperation;
import aws.cryptography.esdk.testserver.server.service.EncryptConcurrentlyOperation;
import aws.cryptography.esdk.testserver.server.service.GetCallCountsOperation;
import software.amazon.smithy.java.server.RequestContext;

/**
 * The test-only operations the caching CMM tests use. This server declares the caching feature
 * unsupported, so the tests never call them; each one rejects the call.
 */
public final class TestOnlyOperationsHandler implements GetCallCountsOperation,
        EncryptConcurrentlyOperation, DecryptConcurrentlyOperation, AdvanceClockOperation {

    @Override
    public GetCallCountsOutput getCallCounts(GetCallCountsInput input, RequestContext context) {
        throw unsupported("GetCallCounts");
    }

    @Override
    public EncryptConcurrentlyOutput encryptConcurrently(
            EncryptConcurrentlyInput input, RequestContext context) {
        throw unsupported("EncryptConcurrently");
    }

    @Override
    public DecryptConcurrentlyOutput decryptConcurrently(
            DecryptConcurrentlyInput input, RequestContext context) {
        throw unsupported("DecryptConcurrently");
    }

    @Override
    public AdvanceClockOutput advanceClock(AdvanceClockInput input, RequestContext context) {
        throw unsupported("AdvanceClock");
    }

    private static GenericServerError unsupported(String operation) {
        return GenericServerError.builder()
            .message(operation + " is not supported by the Java test server")
            .build();
    }
}

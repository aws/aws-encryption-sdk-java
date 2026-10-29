package aws.cryptography.esdk.testserver.server.handler;

import java.nio.ByteBuffer;

/** Small helpers for reading modeled blob members without disturbing them. */
final class Blobs {

    private Blobs() {
    }

    /**
     * Copy the remaining bytes of a {@link ByteBuffer} into a fresh array,
     * duplicating first so the source buffer's position is not consumed.
     */
    static byte[] toArray(ByteBuffer buffer) {
        ByteBuffer duplicate = buffer.duplicate();
        byte[] bytes = new byte[duplicate.remaining()];
        duplicate.get(bytes);
        return bytes;
    }
}

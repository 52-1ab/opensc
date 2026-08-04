package in.captnemo.opensc;

// Uniform driver for "an implementation of libSecureComponent.so's sign/verify
// surface," regardless of how it's actually reached -- in-process JNI, or a
// coprocess speaking the stdin/stdout protocol documented at the top of
// secure_component.c. Letting cross-implementation tests be written once
// against this interface, then run against every backend, is the whole point.
//
// verify() takes the public key explicitly rather than resolving it from the
// alias: two independently-run implementations never share key material, so
// there is no other way to check that one's signature is acceptable to another.
interface ScClient extends AutoCloseable {
    String name();

    byte[] sign(String alias, byte[] data, boolean useEc) throws Exception;

    boolean verify(byte[] pubkeyDer, byte[] data, byte[] sig) throws Exception;

    byte[] pubkey(String alias, String algorithm) throws Exception;

    @Override
    default void close() throws Exception {
    }
}

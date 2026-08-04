package in.librefin.opensc;

// Uniform driver for a libSecureComponent.so implementation, in-process or coprocess, same test suite either way.
interface ScClient extends AutoCloseable {
    String name();

    byte[] sign(String alias, byte[] data, boolean useEc) throws Exception;

    // explicit pubkey, not alias lookup: independent implementations never share key material
    boolean verify(byte[] pubkeyDer, byte[] data, byte[] sig) throws Exception;

    byte[] pubkey(String alias, String algorithm) throws Exception;

    @Override
    default void close() throws Exception {
    }
}

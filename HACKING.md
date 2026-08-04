	mvn test
Compiles the C source fresh (`-DSC_TEST_HOOKS`, adding two test-only natives
that expose internals no real caller can reach) and property-tests it with
[jqwik](https://jqwik.net) against the JDK's own crypto -- UTF-8 conversion
fidelity, RSA-PSS/ECDSA spec conformance, tamper and cross-algorithm
rejection, external-key interop, Base64 robustness, and keystore-alias
isolation/determinism (`SecureComponentPropertyTest`).

A second suite (`CrossImplementationPropertyTest`) drives the same crypto core
through two transports at once -- in-process JNI and the `-DSC_STDIO_SERVER`
coprocess -- behind a common `ScClient` interface, and checks they accept each
other's signatures. That's the seam for adding another language: implement the
stdin/stdout protocol, add an `ScClient`, and the interop properties run against
it unchanged.
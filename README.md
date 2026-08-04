# opensc

Single-file reimplementation of `libSecureComponent.so` -- NPCI's Common Library
(CL), shipped by every UPI app -- covering its three JNI natives on
`org.npci.upi.security.pinactivitycomponent.OfflineNativeDefenderService`:
`nEnableUPILITEX`, `nOfflineSignWithKey`, `nOfflineVerifyEcSignature`.

Behavioral, not bit-for-bit: the real library signs with AndroidKeyStore
hardware-backed keys that can't be reproduced outside a real device, so this
uses real RSA-2048 / P-256 keypairs held in process memory instead, generated
lazily per alias. "Identical" is checked as spec conformance -- every
signature this code produces verifies under the JDK's own independent
`SHA512withRSA/PSS` and `SHA256withECDSA`, and its verifier accepts signatures
produced entirely outside of it. See `secure_component.c`'s header comment and
`src/test/java/.../SecureComponentPropertyTest.java` for what's actually checked.

## Build

JNI shared library, host architecture, no ARM emulator involved:

    gcc -shared -fPIC -O2 -o libSecureComponentRe.so secure_component.c \
        -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/linux" \
        $(pkg-config --cflags --libs openssl) -lpthread

Standalone self-test, no JVM:

    gcc -DSC_TEST_MAIN -O2 -o sc_test secure_component.c \
        $(pkg-config --cflags --libs openssl) -lpthread && ./sc_test

Coprocess server -- no JNI/JVM either, speaks a hex-line sign/verify/pubkey
protocol on stdin/stdout (documented in the file's header comment) so other
implementations, in any language, can be driven and cross-checked the same way:

    gcc -DSC_STDIO_SERVER -O2 -o sc_server secure_component.c \
        $(pkg-config --cflags --libs openssl) -lpthread

## Test

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

Requires `cc`, `pkg-config`, and OpenSSL headers on `PATH`.

## `libSecureComponent/`

Gitignored. The real, proprietary NPCI binaries this project reimplements --
one per host app (PhonePe/Navi/Central Bank/BHIM/KreditBee; see
SECURECOMPONENT-BINDING.md in phonepe-harness) -- distributing them isn't this
project's to do. Drop your own extracted copies here, named `1.so`..`N.so`,
for local reference.

If any are present, `RealLibraryTest` runs against every `*.so` file found in
that directory: it checks each file's SHA1 against the five documented
host-app hashes, then loads it under a plain Maven Central
`unidbg-android`/`unidbg-unicorn2` (not phonepe-harness's vendored/patched
build -- see the pom.xml comment for why that's unneeded here) with a
near-bare JNI bridge, and confirms `JNI_OnLoad` and `nEnableUPILITEX` register
exactly the descriptors this project reimplements. It deliberately never
invokes `nOfflineSignWithKey`/`nOfflineVerifyEcSignature` on the real
libraries -- see `RealLibraryTest`'s class comment for why (a real
KeyStore/Signature bridge would be needed for that, which already exists as
`JniBridge.java` in phonepe-harness and isn't duplicated here). Every test in
that class aborts, rather than fails, when the directory is empty or absent,
so `mvn test` is green either way; failures across files are aggregated per
test rather than stopping at the first bad one.

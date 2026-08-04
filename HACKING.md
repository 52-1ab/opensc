## Build modes (secure_component.c)

    gcc -shared -fPIC -O2 -o libSecureComponentRe.so secure_component.c \
        -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/linux" \
        $(pkg-config --cflags --libs openssl) -lpthread   # JNI shared library

    gcc -DSC_TEST_MAIN -O2 -o sc_test secure_component.c \
        $(pkg-config --cflags --libs openssl) -lpthread && ./sc_test  # standalone self-test, no JVM

    gcc -DSC_STDIO_SERVER -O2 -o sc_server secure_component.c \
        $(pkg-config --cflags --libs openssl) -lpthread   # coprocess server, see protocol below

`-DSC_TEST_HOOKS` adds `nTestUtf8`/`nTestGetPublicKeyDer` to the JNI build --
not part of the real `.so`'s surface, exists only so property tests can check
internals (UTF-8 conversion, per-alias public keys) the real 3-native contract
can't otherwise expose. Never define it for a build meant to stand in for the
genuine library.

`SC_STDIO_SERVER`'s protocol: prints `READY secure_component.c
sign,verify,pubkey` on startup, then one hex-encoded request per line until
EOF or a line reading exactly `QUIT`:

    sign <aliasHex> <dataHex> <useEc:00|01>       -> OK <sigHex>
    verify <pubkeyDerHex> <dataHex> <sigHex>      -> OK 01 / OK 00
    pubkey <aliasHex> <algorithmHex:"RSA"|"EC">   -> OK <derHex>
    (anything else)                               -> ERR <message>

`dataHex` is the UTF-8 bytes of the logical message string (matches
`String.getBytes(UTF_8)`, so other JNI/native implementations observe the same
bytes). `verify` takes the public key explicitly rather than resolving it from
the alias, since independently-run implementations never share key material --
that's what makes cross-implementation interop testing possible at all.

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

A third suite (`RealLibraryTest`) runs end to end against the actual,
proprietary `libSecureComponent.so` copies in `libSecureComponent/`, when
present: real `nOfflineSignWithKey`/`nOfflineVerifyEcSignature` calls into the
genuine binary under `unidbg` ARM64 emulation, backed by `RealLibraryJni` -- a
real software-backed `AndroidKeyStore`/`Signature` JNI bridge, not a stub --
so signatures are real and verification is real, checked against the actual
native code. Every test aborts rather than fails when the directory is empty,
so this is fully optional for anyone without access to the private
`artifacts` submodule.

The important check isn't per-binary round-tripping (sign and verify with the
same copy) -- that alone can't tell a subtly-different binary from an
identical one. It's cross-source: `crossSourceEcdsaSignVerifyMatrixSucceeds`
signs with every one of the five host apps' copies, then verifies every
resulting signature through every *other* copy (full N-by-N, tamper-checked
both ways), which is the actual proof that all five run the identical
algorithm SECURECOMPONENT-BINDING.md's byte-diff claims they do -- not just
that each one is internally consistent with itself.

None of that touches our own reimplementation, though -- a fourth suite
(`RealVsReimplementationTest`) is the actual "is this reimplementation
correct" check: our C code signs, a real binary verifies it; a real binary
signs, our code verifies it; cross-algorithm rejection checked both
directions too. Same abort-when-absent behavior as `RealLibraryTest`.
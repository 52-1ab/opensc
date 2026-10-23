# opensc

Single-file reimplementation of `libSecureComponent.so` backed by OpenSSL, plus `lite/`, a
portable C reimplementation of NPCI's UPI Lite / Lite X wallet.

## Clone

`lite/` vendors [parson](https://github.com/kgabis/parson) as a git submodule, so clone with
submodules:

    git clone --recurse-submodules <repo-url>

Already cloned? Pull the submodule in:

    git submodule update --init lite/third_party/parson

parson is public and required to build `lite/`. The `artifacts/` submodule below is private and
optional (only the real-binary tests need it); a clone without it still builds and tests `lite/`.

## Build

As a JNI shared library exposing the same APIs:

    gcc -shared -fPIC -O2 -o libSecureComponentRe.so secure_component.c \
        -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/linux" \
        $(pkg-config --cflags --libs openssl) -lpthread

## Test

    mvn test

Requires `cc`, `pkg-config`, and OpenSSL headers on `PATH`.

## `artifacts/libSecureComponent/`

A git submodule (private repo: `git@github.com:52-1ab/artifacts.git`) holds
a copy of the upstream binaries that are fetched during tests.
If you have your own libSecureComponent.so (arm64) extracted from official
UPI apps, you can put them in this directory and tests will run against it.

## `lite/`

Portable C23 reimplementation of the UPI Lite / Lite X wallet (vault, riskRules, sync, spend,
Lite X P2P). Build and run the tests (needs the parson submodule, `cc`, `pkg-config`, OpenSSL):

    make -C lite test

## LICENSE

Licensed under [The Unlicense](https://choosealicense.com/licenses/unlicense/). Vendored parson
(`lite/third_party/parson`) is MIT, © Krzysztof Gabis.
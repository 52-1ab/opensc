# opensc

Single-file reimplementation of `libSecureComponent.so`.

## Build

As a JNI shared library exposing the same APIs:

    gcc -shared -fPIC -O2 -o libSecureComponentRe.so secure_component.c \
        -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/linux" \
        $(pkg-config --cflags --libs openssl) -lpthread

## Test

    mvn test

Requires `cc`, `pkg-config`, and OpenSSL headers on `PATH`.

## `libSecureComponent/`

A git submodule (private repo: `git@github.com:52-1ab/artifacts.git`) holds
a copy of the upstream binaries that are fetched during tests.
If you have your own libSecureComponent.so (arm64) extracted from official
UPI apps, you can put them in this directory and tests will run against it.

## LICENSE

Licensed under [The Unlicense](https://choosealicense.com/licenses/unlicense/).
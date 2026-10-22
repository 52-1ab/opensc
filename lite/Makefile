CC ?= cc
CFLAGS ?= -std=c23 -O1 -g -Wall -Wextra -Wpedantic -Werror
SAN := -fsanitize=address,undefined -fno-omit-frame-pointer
INC := -Iinclude
OSSL := $(shell pkg-config --cflags --libs openssl)

SRC := src/codec.c src/json.c src/alias.c src/vault.c src/riskrules.c src/wallet.c src/litex.c
BACKENDS := backends/openssl/crypto_openssl.c backends/mem/keystore_mem.c backends/mem/store_mem.c backends/mem/env_mem.c
LIBSRC := $(SRC) $(BACKENDS)

TESTS := test_codec test_alias test_vault test_wallet test_litex test_litex_flow test_vectors
TESTBIN := $(addprefix build/,$(TESTS))

build/test_wallet: test/test_wallet.c test/npci_test_ca.c $(LIBSRC) | build
	$(CC) $(CFLAGS) $(SAN) $(INC) -Itest test/test_wallet.c test/npci_test_ca.c $(LIBSRC) $(OSSL) -o $@

build/%: test/%.c $(LIBSRC) | build
	$(CC) $(CFLAGS) $(SAN) $(INC) -Itest $< $(LIBSRC) $(OSSL) -o $@

build:
	mkdir -p build

.PHONY: test
test: $(TESTBIN)
	@for t in $(TESTBIN); do echo "== $$t"; ASAN_OPTIONS=detect_leaks=1 $$t || exit 1; done
	@echo "ALL TESTS PASSED"

server: tools/stdio_server.c $(LIBSRC) | build
	$(CC) $(CFLAGS) $(INC) tools/stdio_server.c $(LIBSRC) $(OSSL) -o build/lite_server

vectors: tools/gen_vectors.c $(LIBSRC) | build
	$(CC) $(CFLAGS) $(INC) tools/gen_vectors.c $(LIBSRC) $(OSSL) -o build/gen_vectors
	./build/gen_vectors vectors/vectors.json

oracle-tools: tools/gen_oracle_crosscheck.c tools/check_cl_vault.c tools/gen_sync_cases.c test/npci_test_ca.c $(LIBSRC) | build
	$(CC) $(CFLAGS) $(INC) tools/gen_oracle_crosscheck.c $(LIBSRC) $(OSSL) -o build/gen_oracle_crosscheck
	$(CC) $(CFLAGS) $(INC) tools/check_cl_vault.c $(LIBSRC) $(OSSL) -o build/check_cl_vault
	$(CC) $(CFLAGS) $(INC) -Itest tools/gen_sync_cases.c test/npci_test_ca.c $(LIBSRC) $(OSSL) -o build/gen_sync_cases

.PHONY: clean
clean:
	rm -rf build

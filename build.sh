#!/bin/bash

SECP256K1_DIR=./secp256k1

cd $SECP256K1_DIR

# authgen.sh
sh autogen.sh

# configure secp256k1
CFLAGS="-O3" emconfigure ./configure --enable-module-recovery

# make secp256k1
emmake make

# compile secp256k1.wasm
EMCC_OPTIONS=(
    -O3
    -flto
    -s DISABLE_EXCEPTION_CATCHING=1
    -s MODULARIZE=1
    -s EXPORT_NAME="'SECP256K1'"
    -s ALLOW_MEMORY_GROWTH=0
    -s INVOKE_RUN=1
    -s ERROR_ON_UNDEFINED_SYMBOLS=0
    -s NO_EXIT_RUNTIME=1
    -s NO_DYNAMIC_EXECUTION=1
    -s STRICT=1
)

EMCC_WEB_OPTIONS=(
    # -s ENVIRONMENT=web
    -s NO_FILESYSTEM=1
)

EMCC_SECP256K1_OPTIONS=(
    -s LINKABLE=1
    -s EXPORTED_FUNCTIONS="[ \
        '_secp256k1_context_create', \
        '_secp256k1_context_destroy', \
        '_secp256k1_ec_pubkey_create', \
        '_secp256k1_ec_pubkey_combine', \
        '_secp256k1_ec_pubkey_negate', \
        '_secp256k1_ec_pubkey_parse', \
        '_secp256k1_ec_pubkey_serialize', \
        '_secp256k1_ec_pubkey_tweak_mul', \
        '_secp256k1_ec_seckey_negate', \
        '_secp256k1_ec_seckey_tweak_add', \
        '_secp256k1_ec_seckey_tweak_mul', \
        '_secp256k1_ec_seckey_verify', \
        '_secp256k1_ecdsa_recover', \
        '_secp256k1_ecdsa_recoverable_signature_parse_compact', \
        '_secp256k1_ecdsa_recoverable_signature_serialize_compact', \
        '_secp256k1_ecdsa_sign_recoverable', \
        '_secp256k1_ecdsa_signature_parse_compact', \
        '_secp256k1_ecdsa_verify', \
        '_free', \
        '_malloc' \
    ]"
    -s EXPORTED_RUNTIME_METHODS='["getValue"]'
)

EMCC_WASM_OPTIONS=(
    -s WASM=1
    -s BINARYEN_IGNORE_IMPLICIT_TRAPS=1
    -mnontrapping-fptoint
)

cd ../

echo "Build secp256k1"
emcc "${EMCC_OPTIONS[@]}" "${EMCC_WEB_OPTIONS[@]}" "${EMCC_SECP256K1_OPTIONS[@]}" "${EMCC_WASM_OPTIONS[@]}" $SECP256K1_DIR/.libs/libsecp256k1.a -o ./lib/secp256k1.js

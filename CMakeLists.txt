CMAKE_MINIMUM_REQUIRED(VERSION 3.13) # 3.13: concise relative source paths

SET(CMAKE_C_STANDARD 99)
SET(CMAKE_C_STANDARD_REQUIRED TRUE)

SET(LIBBTC_NAME btc)
PROJECT(lib${LIBBTC_NAME} VERSION 0.1)

INCLUDE(CTest)
SET(USE_TESTS ${CMAKE_TESTING_ENABLED})
SET(WITH_TOOLS TRUE CACHE BOOL "enable bitcoin tool cli application")
SET(WITH_WALLET TRUE CACHE BOOL "enable wallet/database functions")
SET(WITH_NET TRUE CACHE BOOL "enable net functions")
SET(RANDOM_DEVICE "/dev/urandom" CACHE STRING "set the device to read random data from")
IF(WITH_TOOLS OR WITH_WALLET)
    SET(WITH_LOGDB TRUE)
ELSE()
    SET(WITH_LOGDB FALSE)
ENDIF()

IF(WITH_NET)
    FIND_LIBRARY(LIBEVENT event_core REQUIRED)
    IF(WIN32)
        FIND_LIBRARY(LIBEVENT_PTHREADS event_pthreads REQUIRED)
    ENDIF()
ENDIF()

MESSAGE(STATUS "")
MESSAGE(STATUS "Options used to compile and link:")
MESSAGE(STATUS "  WITH_WALLET   = ${WITH_WALLET}")
MESSAGE(STATUS "  WITH_TOOLS    = ${WITH_TOOLS}")
MESSAGE(STATUS "  WITH_NET      = ${WITH_NET}")
MESSAGE(STATUS "")

ADD_DEFINITIONS(
    -DPACKAGE_NAME="${PROJECT_NAME}"
    -DPACKAGE_VERSION="${PROJECT_VERSION}"
    -DRANDOM_DEVICE="${RANDOM_DEVICE}"
)
IF(USE_TESTS)
    ADD_DEFINITIONS(-DUSE_TESTS=1)
ENDIF()
IF(WITH_TOOLS)
    ADD_DEFINITIONS(-DWITH_TOOLS=1)
ENDIF()
IF(WITH_WALLET)
    ADD_DEFINITIONS(-DWITH_WALLET=1)
ENDIF()
IF(WITH_NET)
    ADD_DEFINITIONS(-DWITH_NET=1)
ENDIF()
IF(WITH_LOGDB)
    ADD_DEFINITIONS(-DWITH_LOGDB=1)
ENDIF()
FILE(TOUCH src/libbtc-config.h)


ADD_LIBRARY(${LIBBTC_NAME})

INSTALL(FILES
    include/btc/aes256_cbc.h
    include/btc/base58.h
    include/btc/bip32.h
    include/btc/block.h
    include/btc/blockchain.h
    include/btc/btc.h
    include/btc/buffer.h
    include/btc/chainparams.h
    include/btc/cstr.h
    include/btc/ctaes.h
    include/btc/ecc_key.h
    include/btc/ecc.h
    include/btc/hash.h
    include/btc/hmac.h
    include/btc/memory.h
    include/btc/portable_endian.h
    include/btc/random.h
    include/btc/ripemd160.h
    include/btc/script.h
    include/btc/segwit_addr.h
    include/btc/serialize.h
    include/btc/sha2.h
    include/btc/tool.h
    include/btc/tx.h
    include/btc/utils.h
    include/btc/vector.h
    DESTINATION include/btc
)

INSTALL(FILES
    src/trezor-crypto/base58.h
    src/trezor-crypto/blake2_common.h
    src/trezor-crypto/blake2b.h
    src/trezor-crypto/blake256.h
    src/trezor-crypto/groestl.h
    src/trezor-crypto/groestl_internal.h
    src/trezor-crypto/hasher.h
    src/trezor-crypto/hmac.h
    src/trezor-crypto/memzero.h
    src/trezor-crypto/options.h
    src/trezor-crypto/ripemd160.h
    src/trezor-crypto/segwit_addr.h
    src/trezor-crypto/sha2.h
    src/trezor-crypto/sha3.h
    DESTINATION include/trezor-crypto
)

TARGET_SOURCES(${LIBBTC_NAME} PRIVATE
    src/aes256_cbc.c
    src/base58.c
    src/bip32.c
    src/block.c
    src/buffer.c
    src/chainparams.c
    src/commontools.c
    src/cstr.c
    src/ctaes.c
    src/ecc_key.c
    src/ecc_libsecp256k1.c
    src/memory.c
    src/random.c
    src/ripemd160.c
    src/script.c
    src/serialize.c
    src/tx.c
    src/utils.c
    src/vector.c
)

TARGET_SOURCES(${LIBBTC_NAME} PRIVATE
    src/trezor-crypto/base58.c
    src/trezor-crypto/blake2b.c
    src/trezor-crypto/blake256.c
    src/trezor-crypto/groestl.c
    src/trezor-crypto/hasher.c
    src/trezor-crypto/hmac.c
    src/trezor-crypto/memzero.c
    src/trezor-crypto/ripemd160.c
    src/trezor-crypto/segwit_addr.c
    src/trezor-crypto/sha2.c
    src/trezor-crypto/sha3.c
)

FILE(GLOB SECP256K1 RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    src/secp256k1/src/*.c)
LIST(REMOVE_ITEM SECP256K1
    src/secp256k1/src/tests.c
    src/secp256k1/src/tests_exhaustive.c
    src/secp256k1/src/bench_ecdh.c
    src/secp256k1/src/bench_ecmult.c
    src/secp256k1/src/bench_recover.c
    src/secp256k1/src/bench_sign.c
    src/secp256k1/src/bench_verify.c
    src/secp256k1/src/bench_ecdh.c
    src/secp256k1/src/bench_internal.c
    src/secp256k1/src/bench_schnorr_verify.c
    src/secp256k1/src/valgrind_ctime_test.c)
ADD_DEFINITIONS(
    -DUSE_NUM_GMP
    -DUSE_FIELD_10X26
    -DUSE_FIELD_INV_BUILTIN
    -DUSE_SCALAR_8X32
    -DUSE_SCALAR_INV_BUILTIN
    -DENABLE_MODULE_RECOVERY
    -DECMULT_WINDOW_SIZE=15
    -DECMULT_GEN_PREC_BITS=4)
TARGET_SOURCES(${LIBBTC_NAME} PRIVATE ${SECP256K1})

INCLUDE_DIRECTORIES(
    include
    src/logdb/include
    src/secp256k1
    ${GMP_INSTALL_DIR}/include)

IF(USE_TESTS)
    ADD_EXECUTABLE(tests)
    TARGET_SOURCES(tests PRIVATE
        test/aes_tests.c
        test/base58check_tests.c
        test/bip32_tests.c
        test/block_tests.c
        test/buffer_tests.c
        test/cstr_tests.c
        test/ecc_tests.c
        test/eckey_tests.c
        test/hash_tests.c
        test/memory_tests.c
        test/random_tests.c
        test/serialize_tests.c
        test/sha2_tests.c
        test/unittester.c
        test/tx_tests.c
        test/utils_tests.c
        test/vector_tests.c
    )
    TARGET_LINK_LIBRARIES(tests ${LIBBTC_NAME})
    ADD_TEST(NAME ${LIBBTC_NAME}_tests COMMAND tests)
ENDIF()

IF(WITH_LOGDB)
    TARGET_SOURCES(${LIBBTC_NAME} PRIVATE
        src/logdb/logdb_core.c
        src/logdb/logdb_memdb_llist.c
        src/logdb/logdb_memdb_rbtree.c
        src/logdb/logdb_rec.c
        src/logdb/red_black_tree.c
    )
    INSTALL(FILES
        src/logdb/include/logdb/logdb_base.h
        src/logdb/include/logdb/logdb_core.h
        src/logdb/include/logdb/logdb_memdb_llist.h
        src/logdb/include/logdb/logdb_memdb_rbtree.h
        src/logdb/include/logdb/logdb_rec.h
        src/logdb/include/logdb/logdb.h
        src/logdb/include/logdb/red_black_tree.h
        DESTINATION include/logdb
    )
    IF(USE_TESTS)
        TARGET_SOURCES(tests PRIVATE
            src/logdb/test/logdb_tests.c
            src/logdb/test/tests_red_black_tree.c
        )
    ENDIF()
ENDIF()

IF(WITH_WALLET)
    INSTALL(FILES
        include/btc/wallet.h
        DESTINATION include/btc
    )
    TARGET_SOURCES(${LIBBTC_NAME} PRIVATE
        src/wallet.c
    )
    IF(USE_TESTS)
        TARGET_SOURCES(tests PRIVATE
            test/wallet_tests.c
        )
    ENDIF()
ENDIF()

IF(WITH_NET)
    INSTALL(FILES
        include/btc/headersdb.h
        include/btc/headersdb_file.h
        include/btc/protocol.h
        include/btc/net.h
        include/btc/netspv.h
        DESTINATION include/btc
    )
    TARGET_SOURCES(${LIBBTC_NAME} PRIVATE
        src/headersdb_file.c
        src/net.c
        src/netspv.c
        src/protocol.c
    )

    TARGET_LINK_LIBRARIES(${LIBBTC_NAME} ${LIBEVENT} ${LIBEVENT_PTHREADS})

    IF(USE_TESTS)
        TARGET_SOURCES(tests PRIVATE
            test/net_tests.c
            test/netspv_tests.c
            test/protocol_tests.c
        )
    ENDIF()
ENDIF()

IF(WITH_TOOLS)
    IF(USE_TESTS)
        TARGET_SOURCES(tests PRIVATE
            test/tool_tests.c
        )
    ENDIF()

    ADD_EXECUTABLE(bitcointool src/tools/bitcointool.c)
    INSTALL(TARGETS bitcointool RUNTIME)
    TARGET_LINK_LIBRARIES(bitcointool ${LIBBTC_NAME})
    TARGET_INCLUDE_DIRECTORIES(bitcointool PRIVATE src)

    IF(WITH_NET)
        ADD_EXECUTABLE(bitcoin-send-tx src/tools/bitcoin-send-tx.c)
        INSTALL(TARGETS bitcoin-send-tx RUNTIME)
        TARGET_LINK_LIBRARIES(bitcoin-send-tx ${LIBBTC_NAME})
        TARGET_INCLUDE_DIRECTORIES(bitcoin-send-tx PRIVATE src)
        ADD_EXECUTABLE(bitcoin-spv src/tools/bitcoin-spv.c)
        INSTALL(TARGETS bitcoin-spv RUNTIME)
        TARGET_LINK_LIBRARIES(bitcoin-spv ${LIBBTC_NAME})
        TARGET_INCLUDE_DIRECTORIES(bitcoin-spv PRIVATE src)
    ENDIF()
ENDIF()


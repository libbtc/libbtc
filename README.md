libbtc – A Simple and Effective C Library for Bitcoin Wallets
=============================================================

[![Build Status](https://travis-ci.org/libbtc/libbtc.svg?branch=master)](https://travis-ci.org/libbtc/libbtc)  [![Coverage Status](https://coveralls.io/repos/libbtc/libbtc/badge.svg?branch=master&service=github)](https://coveralls.io/github/libbtc/libbtc?branch=master)

What is libbtc?
----------------

Libbtc is a simple and portable C library for creating and manipulating bitcoin data structures like creating keys and addresses (HD/bip32) or parsing, creating and signing transactions.

What is the Focus of Libbtc?
----------------

* minimum dependencies (only dependency libsecp256k1)
* optimized for low mem environments like embedded/MCU
* full test coverage
* mem leak free (valgrind check during CI)

How to Build
----------------
```
./autogen.sh
./configure
make check
```

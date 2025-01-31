# EnCryptoPP

## Introduction

This is a library and tool used to leverage anything to do with cryptography, from AES, RSA
to full JWT Implementations

## Usage

To be used as a link library to other projects and as a standalone tool for leveraging
encryption/decryption in a terminal.  All memory is allocated and deallocated with zero out
capability aka Secure strings are used so that memory can never be peeked or poked during
encryption and decryption or passing of sensitive keys.

## Compilation

There is a known issue with the library jsoncpp.

baylesj, a contributor stated on Sep 12, 2024

```
We haven't had capacity to fix CMake related issues, as you have likely noticed. If you want to submit a patch for 
review I would be happy to review it.
```

To resolve this linkage error for now, ensure the latest tag is pulled for the jsoncpp submodule which is version 1.9.6

## Third Party Library Dependencies

| Name       | Repository |
|------------|------------|
| googletest | https://github.com/google/googletest.git |
| magic_enum | https://github.com/Neargye/magic_enum.git |
| jwt-cpp    | https://github.com/Thalhammer/jwt-cpp.git |
| argparse  | https://github.com/morrisfranken/argparse.git |
| jsoncpp    | https://github.com/open-source-parsers/jsoncpp.git |

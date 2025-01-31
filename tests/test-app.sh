#!/usr/bin/env bash

# Check if exactly one argument is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 {debug|release}"
    exit 1
fi

# Get the argument
arg=$1

# Check if the argument is one of the allowed values
if [ "$arg" != "debug" ] && [ "$arg" != "release" ]; then
    echo "Error: Argument must be 'debug' or 'release'"
    exit 1
fi

encryptopp="./cmake-build-${arg}/bin/encryptopp"

test_clear_text="some clear text that needs to be encrypted."

####
# Help test
####

./"${encryptopp}" -?
./"${encryptopp}" --help

./"${encryptopp}" -v
./"${encryptopp}" --version

###
# Aes EncryptDecrypt Test
###

cipher_text=$(./"${encryptopp}" aes -e "my_secret" -i "my_init_vector" "${test_clear_text}")
clear_text=$(./"${encryptopp}" aes -d "my_secret" -i "my_init_vector" "${cipher_text}")

if [[ "${test_clear_text}" != "${clear_text}" ]]; then
  printf "\nError running AES Encrypt/Decrypt\n"
  exit 1
fi

cipher_text=$(./"${encryptopp}" aes --encrypt "my_secret" --initvector "my_init_vector" "${test_clear_text}")
clear_text=$(./"${encryptopp}" aes --decrypt "my_secret" --initvector "my_init_vector" "${cipher_text}")

if [[ "${test_clear_text}" != "${clear_text}" ]]; then
  printf "\nError running AES Encrypt/Decrypt\n"
  exit 1
fi

###
# Aes SignVerify Test
###

signature_text=$(./"${encryptopp}" aes -s "my_secret" "${test_clear_text}")
./"${encryptopp}" aes -v "my_secret" -x "${signature_text}" "${test_clear_text}" 2>&1

if [[ $? == 1 ]]; then
  printf "\nError running AES Sign/Verify\n"
  exit 1
fi

signature_text=$(./"${encryptopp}" aes --sign "my_secret" "${test_clear_text}")
./"${encryptopp}" aes --verify "my_secret" --signature "${signature_text}" "${test_clear_text}" 2>&1

if [[ $? == 1 ]]; then
  printf "\nError running AES Sign/Verify\n"
  exit 1
fi
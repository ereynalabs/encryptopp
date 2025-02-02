/**
* @copyright Copyright (C) 2025, Ereyna Labs Ltd. - All Rights Reserved
 * @file ShaCtrlBase.cc
 * @parblock
 * This file is subject to the terms and conditions defined in file 'LICENSE.md',
 * which is part of this source code package.  Proprietary and confidential.
 * @endparblock
 * @author Dave Linten <david@ereynalabs.com>
 */

#include "ShaCtrlBase.h"

#include <string>
#include <iostream>
#include <iomanip>
#include <ctime>
#include <openssl/evp.h>
#include <random>
#include <sstream>

namespace encryptopp {
    namespace {
        enum HASH_ALGO {
            SHA1,
            SHA256,
            SHA512
        };

        void hash(const string::secure_string& clear_text,
                  const HASH_ALGO algorithm,
                  std::function<void(const string::secure_string& cipher_text)>&& success_callback,
                  std::function<void(const string::secure_string& error_message)>&& failure_callback) {
            typedef unsigned char byte;

            EVP_MD_CTX* ctx;
            ctx = EVP_MD_CTX_new();
            byte digest[EVP_MAX_MD_SIZE];
            unsigned int outLen;

            switch (algorithm) {
                case SHA1:
                    EVP_DigestInit(ctx, EVP_sha1());
                    break;
                case SHA256:
                    EVP_DigestInit(ctx, EVP_sha256());
                    break;
                case SHA512:
                    EVP_DigestInit(ctx, EVP_sha512());
                    break;
            }

            EVP_DigestUpdate(ctx, clear_text.data(), clear_text.length());
            EVP_DigestFinal(ctx, digest, &outLen);

            EVP_MD_CTX_free(ctx);

            std::stringstream ss;
            for (unsigned int i = 0; i < outLen; i++)
                ss << std::setfill('0') << std::setw(2) << std::hex << (int)digest[i];

            string::secure_string ret{ss.str()};
            (success_callback)(ret);
        }
    }

    void ShaBase::sha1_hash(const string::secure_string& clear_text,
                                std::function<void(const string::secure_string& cipher_text)>&& success_callback,
                                std::function<void(const string::secure_string& error_message)>&& failure_callback) {
        hash(clear_text, SHA1, std::move(success_callback), std::move(failure_callback));
    }

    void ShaBase::sha256_hash(const string::secure_string& clear_text,
                                  std::function<void(const string::secure_string& cipher_text)>&& success_callback,
                                  std::function<void(const string::secure_string& error_message)>&& failure_callback) {
        hash(clear_text, SHA256, std::move(success_callback), std::move(failure_callback));
    }

    void ShaBase::sha512_hash(const string::secure_string& clear_text,
                                  std::function<void(const string::secure_string& cipher_text)>&& success_callback,
                                  std::function<void(const string::secure_string& error_message)>&& failure_callback) {
        hash(clear_text, SHA512, std::move(success_callback), std::move(failure_callback));
    }

}

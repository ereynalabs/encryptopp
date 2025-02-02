/**
* @copyright Copyright (C) 2024, Ereyna Labs Ltd. - All Rights Reserved
 * @file RsaCtrlBase.cc
 * @parblock
 * This file is subject to the terms and conditions defined in file 'LICENSE.md',
 * which is part of this source code package.  Proprietary and confidential.
 * @endparblock
 * @author Dave Linten <david@ereynalabs.com>
 */

#include "RsaCtrlBase.h"

#include <string>
#include <memory>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>

namespace encryptopp {
    // namespace {
    //     // Convert binary data to base64 string
    //     string::secure_string base64_encode(const string::secure_string& input, const unsigned long length) {
    //         BUF_MEM* buffer_ptr;
    //
    //         BIO* b64 = BIO_new(BIO_f_base64());
    //         BIO* bio = BIO_new(BIO_s_mem());
    //         bio = BIO_push(b64, bio);
    //
    //         BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    //         BIO_write(bio, input.c_str(), length);
    //         BIO_flush(bio);
    //         BIO_get_mem_ptr(bio, &buffer_ptr);
    //
    //         string::secure_string result(buffer_ptr->data, buffer_ptr->length);
    //
    //         BIO_free_all(bio);
    //
    //         return result;
    //     }
    //
    //     // Convert base64 string to binary data
    //     string::secure_string base64_decode(const string::secure_string& input) {
    //         unsigned char buffer[input.size()];
    //         memset(buffer, 0, input.size());
    //
    //         BIO* bio = BIO_new_mem_buf(input.c_str(), -1);
    //         BIO* b64 = BIO_new(BIO_f_base64());
    //         bio = BIO_push(b64, bio);
    //
    //         BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    //         const int length = BIO_read(bio, buffer, input.size());
    //
    //         string::secure_string result(reinterpret_cast<char *>(buffer), length);
    //
    //         BIO_free_all(bio);
    //
    //         return result;
    //     }
    // }

    void RsaBase::encrypt(const string::secure_string &public_key,
                              const string::secure_string &clear_text,
                              std::function<void(const string::secure_string &cipher_text)> &&success_callback,
                              std::function<void(const string::secure_string &error_message)> &&failure_callback) {
        BIO *bio = BIO_new_mem_buf(public_key.c_str(), -1);
        EVP_PKEY *evp_public_key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (!evp_public_key) {
            (failure_callback)("Failed to read public key");
            return;
        }

        size_t encrypted_data_length = 0;

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(evp_public_key, nullptr);
        if (!ctx) {
            EVP_PKEY_free(evp_public_key);
            (failure_callback)("Failed to create EVP_PKEY_CTX");
            return;
        }

        if (EVP_PKEY_encrypt_init(ctx) <= 0 ||
            EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0 ||
            EVP_PKEY_encrypt(ctx, nullptr, &encrypted_data_length,
                             reinterpret_cast<const unsigned char *>(clear_text.c_str()), clear_text.length()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(evp_public_key);
            (failure_callback)("Failed to get size of encrypted data");
            return;
        }

        auto *encrypted_data = new unsigned char[encrypted_data_length];

        if (EVP_PKEY_encrypt(ctx, encrypted_data, &encrypted_data_length,
                             reinterpret_cast<const unsigned char *>(clear_text.c_str()), clear_text.length()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(evp_public_key);
            delete[] encrypted_data;
            (failure_callback)("Failed to encrypt data");
            return;
        }

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(evp_public_key);

        const string::secure_string encrypted_string(reinterpret_cast<char *>(encrypted_data), encrypted_data_length);
        delete[] encrypted_data;

        Base64Base::encode(encrypted_string, std::move(success_callback), std::move(failure_callback), true, true);
        // const string::secure_string base64_cipher_text{base64_encode(encrypted_string, encrypted_string.length())};
        // (success_callback)(base64_cipher_text);
    }

    void RsaBase::sign(const string::secure_string &private_key,
                           const string::secure_string &clear_text,
                           std::function<void(const string::secure_string &cipher_text)> &&success_callback,
                           std::function<void(const string::secure_string &error_message)> &&failure_callback) {
        BIO *bio = BIO_new_mem_buf(private_key.c_str(), -1);
        EVP_PKEY *evp_private_key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (!evp_private_key) {
            (failure_callback)("Failed to read private key");
            return;
        }

        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx) {
            EVP_PKEY_free(evp_private_key);
            (failure_callback)("Failed to create EVP_MD_CTX");
            return;
        }

        if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, evp_private_key) <= 0 ||
            EVP_DigestSignUpdate(ctx, clear_text.c_str(), clear_text.length()) <= 0) {
            EVP_MD_CTX_free(ctx);
            EVP_PKEY_free(evp_private_key);
            (failure_callback)("Failed to initialize signature");
            return;
        }

        size_t sigLen;
        if (EVP_DigestSignFinal(ctx, nullptr, &sigLen) <= 0) {
            EVP_MD_CTX_free(ctx);
            EVP_PKEY_free(evp_private_key);
            (failure_callback)("Failed to get signature length");
            return;
        }

        std::unique_ptr<unsigned char[]> sig(new unsigned char[sigLen]);
        if (EVP_DigestSignFinal(ctx, sig.get(), &sigLen) <= 0) {
            EVP_MD_CTX_free(ctx);
            EVP_PKEY_free(evp_private_key);
            (failure_callback)("Failed to finalize signature");
            return;
        }

        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(evp_private_key);

        const string::secure_string signature(reinterpret_cast<char *>(sig.get()), sigLen);

        Base64Base::encode(signature, std::move(success_callback), std::move(failure_callback), true, true);

        //const string::secure_string base64_signature{base64_encode(signature, signature.length())};
        //(success_callback)(base64_signature);
    }

    void RsaBase::verify(const string::secure_string &public_key,
                             const string::secure_string &clear_text,
                             const string::secure_string &signature,
                             std::function<void()> &&success_callback,
                             std::function<void(const string::secure_string &error_message)> &&failure_callback) {
        Base64Base::decode(
            signature,
            [public_key, clear_text, success_callback, failure_callback](const string::secure_string &decoed_text) {
                BIO *bio = BIO_new_mem_buf(public_key.c_str(), -1);
                EVP_PKEY *evp_public_key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
                BIO_free(bio);

                if (!evp_public_key) {
                    (failure_callback)("Failed to read public key");
                    return;
                }
                EVP_MD_CTX *ctx = EVP_MD_CTX_new();
                if (!ctx) {
                    EVP_PKEY_free(evp_public_key);
                    (failure_callback)("Failed to create EVP_MD_CTX");
                    return;
                }

                if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, evp_public_key) <= 0 ||
                    EVP_DigestVerifyUpdate(ctx, clear_text.c_str(), clear_text.length()) <= 0 ||
                    EVP_DigestVerifyFinal(ctx, reinterpret_cast<const unsigned char *>(decoed_text.c_str()),
                                          decoed_text.length()) <= 0) {
                    EVP_MD_CTX_free(ctx);
                    EVP_PKEY_free(evp_public_key);
                    (failure_callback)("Failed to verify signature");
                    return;
                }

                EVP_MD_CTX_free(ctx);
                EVP_PKEY_free(evp_public_key);

                (success_callback)();
            }, [failure_callback](const string::secure_string &error_message) {
                (failure_callback)(error_message);
            });
    }

    void RsaBase::decrypt(const string::secure_string &private_key,
                              const string::secure_string &cipher_text,
                              std::function<void(const string::secure_string &clear_text)> &&success_callback,
                              std::function<void(const string::secure_string &error_message)> &&failure_callback) {
        Base64Base::decode(cipher_text,
                               [private_key, success_callback, failure_callback](
                           const string::secure_string &decoded_text) {
                                   BIO *bio = BIO_new_mem_buf(private_key.c_str(), -1);
                                   EVP_PKEY *privateKey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
                                   BIO_free(bio);

                                   if (!privateKey) {
                                       (failure_callback)("Failed to read private key");
                                       return;
                                   }

                                   size_t decrypted_length = 0;

                                   EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privateKey, nullptr);

                                   if (!ctx) {
                                       EVP_PKEY_free(privateKey);
                                       (failure_callback)("Failed to create EVP_PKEY_CTX");
                                       return;
                                   }

                                   if (EVP_PKEY_decrypt_init(ctx) <= 0 ||
                                       EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0 ||
                                       EVP_PKEY_decrypt(ctx, nullptr, &decrypted_length,
                                                        reinterpret_cast<const unsigned char *>(decoded_text.c_str()),
                                                        decoded_text.length()) <= 0) {
                                       EVP_PKEY_CTX_free(ctx);
                                       EVP_PKEY_free(privateKey);
                                       (failure_callback)("Failed to get size of decrypted data");
                                       return;
                                   }

                                   auto *decrypted = new unsigned char[decrypted_length];

                                   if (EVP_PKEY_decrypt(ctx, decrypted, &decrypted_length,
                                                        reinterpret_cast<const unsigned char *>(decoded_text.c_str()),
                                                        decoded_text.length()) <= 0) {
                                       EVP_PKEY_CTX_free(ctx);
                                       EVP_PKEY_free(privateKey);
                                       delete[] decrypted;
                                       (failure_callback)("Failed to decrypt data");
                                       return;
                                   }

                                   EVP_PKEY_CTX_free(ctx);
                                   EVP_PKEY_free(privateKey);

                                   string::secure_string decryptedString(
                                       reinterpret_cast<char *>(decrypted), decrypted_length);
                                   delete[] decrypted;
                                   (success_callback)(decryptedString);
                               }, [failure_callback](const string::secure_string &error_message) {
                                   (failure_callback)(error_message);
                               });
    }

    void RsaBase::generate_keypair(
        std::function<void(const string::secure_string &private_key, const string::secure_string &public_key)> &&
        success_callback, std::function<void(const string::secure_string &error_message)> &&failure_callback) {
        const int keyLength = 2048;

        EVP_PKEY_CTX *ctx;
        EVP_PKEY *key = nullptr;

        // Create context
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!ctx) {
            (failure_callback)("Failed to create EVP_PKEY_CTX");
            return;
        }

        // Initialize key generation
        if (EVP_PKEY_keygen_init(ctx) <= 0 ||
            EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keyLength) <= 0 ||
            EVP_PKEY_keygen(ctx, &key) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            (failure_callback)("Failed to generate RSA key pair");
            return;
        }

        EVP_PKEY_CTX_free(ctx);

        // Convert public key to string
        BIO *publicKeyBio = BIO_new(BIO_s_mem());
        PEM_write_bio_PUBKEY(publicKeyBio, key);
        BUF_MEM *publicKeyPtr;
        BIO_get_mem_ptr(publicKeyBio, &publicKeyPtr);
        string::secure_string publicKeyStr(publicKeyPtr->data, publicKeyPtr->length);
        BIO_free(publicKeyBio);

        // Convert private key to string
        BIO *privateKeyBio = BIO_new(BIO_s_mem());
        PEM_write_bio_PrivateKey(privateKeyBio, key, nullptr, nullptr, 0, nullptr, nullptr);
        BUF_MEM *privateKeyPtr;
        BIO_get_mem_ptr(privateKeyBio, &privateKeyPtr);
        string::secure_string privateKeyStr(privateKeyPtr->data, privateKeyPtr->length);
        BIO_free(privateKeyBio);

        EVP_PKEY_free(key);

        (success_callback)(privateKeyStr, publicKeyStr);
    }
}

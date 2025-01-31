/**
 * @copyright Copyright (C) 2024, Ereyna Labs Ltd. - All Rights Reserved
 * @file AesCtrlBase.cc
 * @parblock
 * This file is subject to the terms and conditions defined in file 'LICENSE.md',
 * which is part of this source code package.  Proprietary and confidential.
 * @endparblock
 * @author Dave Linten <david@ereynalabs.com>
 */

#include "AesCtrlBase.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <iostream>
#include <string>
#include <cstring>

namespace encryptopp {
    namespace {
        // template<const unsigned Num, const char Separator>
        // void separate(std::string& input) {
        //     for (auto it = input.begin(); (Num + 1) <= std::distance(it, input.end()); ++it) {
        //         std::advance(it, Num);
        //         it = input.insert(it, Separator);
        //     }
        // }

        // void pad_to(string::secure_string& str, const size_t num, const char padding_char = '\0') {
        void pad_to(string::secure_string &str, const size_t num) {
            str.append(num - str.length() % num, '\0');
        }

        void unpad_to(string::secure_string &str, const size_t num) {
            str.resize(num);
        }

        //void reference_pad(string::secure_string& str, const size_t num, const char padding_char = '\0') {
        void reference_pad(string::secure_string &str, const size_t num) {
            //Equals assumed by logic, do nothing
            if (str.length() < num) {
                // pad_to(str, num, '\0');
                pad_to(str, num);
            }

            if (str.length() > num) {
                unpad_to(str, num);
            }
        }

        //     // Convert binary data to base64 string
        //     string::secure_string base64_encode(const string::secure_string& input) {
        //         BIO* bio = BIO_new(BIO_s_mem());
        //         BIO* b64 = BIO_new(BIO_f_base64());
        //         BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        //         bio = BIO_push(b64, bio);
        //         BIO_write(bio, input.c_str(), input.length());
        //         BIO_flush(bio);
        //         BUF_MEM* buffer_ptr;
        //         BIO_get_mem_ptr(bio, &buffer_ptr);
        //         string::secure_string encoded(buffer_ptr->data, buffer_ptr->length);
        //         BIO_free_all(bio);
        //         return encoded;
        //     }
        //
        //     // Convert base64 string to binary data
        //     string::secure_string base64_decode(const string::secure_string& input) {
        //         BIO* bio = BIO_new_mem_buf(input.c_str(), -1);
        //         BIO* b64 = BIO_new(BIO_f_base64());
        //         BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        //         bio = BIO_push(b64, bio);
        //         char buffer[1024];
        //         string::secure_string decoded;
        //         int length;
        //         while ((length = BIO_read(bio, buffer, 1024)) > 0) {
        //             decoded.append(buffer, length);
        //         }
        //         BIO_free_all(bio);
        //         return decoded;
        //     }
    }

    constexpr unsigned int key_size = 32;
    constexpr unsigned int block_size = 16;
    using byte = unsigned char;
    using evp_cipher_ctx_free_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;

    AesBase::AesBase() = default;

    void AesBase::encrypt(const string::secure_string &key,
                              const string::secure_string &iv,
                              const string::secure_string &clear_text,
                              std::function<void(const string::secure_string &)> &&success_callback,
                              std::function<void(const string::secure_string &)> &&failure_callback) {
        try {
            string::secure_string temp_key{key};
            string::secure_string temp_iv{iv};

            reference_pad(temp_key, key_size);
            reference_pad(temp_iv, block_size);

            string::secure_string cipher_text;
            byte key_bytes[key_size];
            byte iv_bytes[block_size];

            // Load the necessary cipher
            int rc = EVP_add_cipher(EVP_aes_256_cbc());
            if (rc != 1) {
                (failure_callback)("EVP_add_cipher failed");
                return;
            }

            std::ranges::copy(temp_key.begin(), temp_key.end(), key_bytes);
            std::ranges::copy(temp_iv.begin(), temp_iv.end(), iv_bytes);

            const evp_cipher_ctx_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
            rc = EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key_bytes, iv_bytes);
            if (rc != 1) {
                (failure_callback)("EVP_EncryptInit_ex failed");
                return;
            }

            // Recovered text expands upto block_size
            cipher_text.resize(clear_text.size() + block_size);
            int out_len1 = static_cast<int>(cipher_text.size());

            rc = EVP_EncryptUpdate(ctx.get(), reinterpret_cast<byte *>(&cipher_text[0]), &out_len1,
                                   reinterpret_cast<const byte *>(&clear_text[0]),
                                   static_cast<int>(clear_text.size()));
            if (rc != 1) {
                (failure_callback)("EVP_EncryptUpdate failed");
                return;
            }

            int out_len2 = static_cast<int>(cipher_text.size()) - out_len1;
            rc = EVP_EncryptFinal_ex(ctx.get(), reinterpret_cast<byte *>(&cipher_text[0]) + out_len1, &out_len2);
            if (rc != 1) {
                (failure_callback)("EVP_EncryptFinal_ex failed");
                return;
            }

            // Set cipher text size now that we know it
            cipher_text.resize(out_len1 + out_len2);

            Base64Base::encode(cipher_text, [success_callback](const string::secure_string &encoded_text) {
                                       (success_callback)(encoded_text);
                                   }, [failure_callback](const string::secure_string &error_message) {
                                       (failure_callback)(error_message);
                                   }, true, true);
            // (success_callback)(base64_encode(cipher_text));
        } catch (const std::exception &ex) {
            (failure_callback)(ex.what());
        }
    }

    void AesBase::decrypt(const string::secure_string &key,
                              const string::secure_string &iv,
                              const string::secure_string &cipher_text,
                              std::function<void(const string::secure_string &clear_text)> &&success_callback,
                              std::function<void(const string::secure_string &error_message)> &&failure_callback) {
        Base64Base::decode(cipher_text, [key, iv, success_callback, failure_callback](
                           const string::secure_string &decoded_text) {
                                   try {
                                       string::secure_string temp_key{key};
                                       string::secure_string temp_iv{iv};
                                       string::secure_string temp_cipher_text{decoded_text};

                                       // Load the necessary cipher
                                       int rc = EVP_add_cipher(EVP_aes_256_cbc());
                                       if (rc != 1) {
                                           (failure_callback)("EVP_add_cipher failed");
                                           return;
                                       }


                                       reference_pad(temp_key, key_size);
                                       reference_pad(temp_iv, block_size);

                                       byte key_bytes[key_size];
                                       byte iv_bytes[block_size];

                                       std::ranges::copy(temp_key.begin(), temp_key.end(), key_bytes);
                                       std::ranges::copy(temp_iv.begin(), temp_iv.end(), iv_bytes);
                                       string::secure_string clear_text;

                                       const evp_cipher_ctx_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
                                       rc = EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key_bytes,
                                                               iv_bytes);
                                       if (rc != 1) {
                                           (failure_callback)("EVP_DecryptInit_ex failed");
                                           return;
                                       }

                                       // Recovered text contracts upto block_size
                                       clear_text.resize(temp_cipher_text.size());
                                       int out_len1 = static_cast<int>(clear_text.size());

                                       rc = EVP_DecryptUpdate(ctx.get(), reinterpret_cast<byte *>(&clear_text[0]),
                                                              &out_len1,
                                                              reinterpret_cast<const byte *>(&temp_cipher_text[0]),
                                                              static_cast<int>(temp_cipher_text.size()));
                                       if (rc != 1) {
                                           (failure_callback)("EVP_DecryptUpdate failed");
                                           return;
                                       }

                                       int out_len2 = static_cast<int>(clear_text.size()) - out_len1;
                                       clear_text.resize(out_len1 + out_len2);

                                       rc = EVP_DecryptFinal_ex(
                                           ctx.get(), reinterpret_cast<byte *>(&clear_text[0]) + out_len1, &out_len2);
                                       if (rc != 1) {
                                           string::secure_string error_message{"EVP_DecryptFinal_ex failed "};
                                           error_message.append(ERR_error_string(ERR_get_error(), nullptr));
                                           (failure_callback)(error_message);
                                           return;
                                       }

                                       // Set recovered text size now that we know it
                                       clear_text.resize(out_len1 + out_len2);

                                       (success_callback)(clear_text);
                                   } catch (std::exception &ex) {
                                       (failure_callback)(ex.what());
                                   }
                               }, [failure_callback](const string::secure_string &error_message) {
                                   (failure_callback)(error_message);
                               });
    }

    void AesBase::sign(const string::secure_string &key,
                           const string::secure_string &clear_text,
                           std::function<void(const string::secure_string &signature)> &&success_callback,
                           std::function<void(const string::secure_string &error_message)> &&failure_callback) {
        // unsigned char digest[EVP_MAX_MD_SIZE];
        // unsigned int digest_length;
        //
        // // Compute HMAC
        // HMAC(EVP_sha256(), key.c_str(), key.length(), reinterpret_cast<const unsigned char *>(clear_text.c_str()),
        //      clear_text.length(), digest, &digest_length);

        // // Convert digest to hexadecimal string
        // string::secure_string result;
        // for (unsigned int i = 0; i < digest_length; ++i) {
        //     char buf[3];
        //     sprintf(buf, "%02x", digest[i]);
        //     result += buf;
        // }
        unsigned int digest_len;
        unsigned char *digest = HMAC(EVP_sha256(), key.c_str(), key.length(),
                                     reinterpret_cast<const unsigned char *>(clear_text.c_str()), clear_text.length(), nullptr, &digest_len);

        if (!digest) {
            (failure_callback)("HMAC failed");
            return;
        }

        const string::secure_string secure_digest { reinterpret_cast<char*>(digest), digest_len };
        Base64Base::encode(secure_digest, [success_callback](const string::secure_string& encoded_text) {
            (success_callback)(encoded_text);
        }, std::move(failure_callback), false, true);
    }

    /// This function will check against base64 encoded signatures, NOT the binary octet as intended by OpenSSL
    void AesBase::verify(const string::secure_string &key,
                             const string::secure_string &clear_text,
                             const string::secure_string &signature,
                             std::function<void()> &&success_callback,
                             std::function<void(const string::secure_string &error_message)> &&failure_callback) {
        sign(key, clear_text,
             [signature, success_callback, failure_callback](const string::secure_string &computed_signature) {
                 if (computed_signature == signature) {
                     (success_callback)();
                     return;
                 }

                 (failure_callback)("The signature is incorrect for the data supplied");
             }, [failure_callback](const string::secure_string &error_message) {
                 (failure_callback)(error_message);
             });
    }
}

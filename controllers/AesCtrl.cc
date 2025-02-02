/**
 * @copyright Copyright (C) 2025, Ereyna Labs Ltd. - All Rights Reserved
 * @file AesCtrl.cc
 * @parblock
 * This file is subject to the terms and conditions defined in file 'LICENSE.md',
 * which is part of this source code package.  Proprietary and confidential.
 * @endparblock
 * @author Dave Linten <david@ereynalabs.com>
 */

#include "AesCtrl.h"
#include <future>

namespace encryptopp {
    void Aes::encrypt(const string::secure_string &key,
                      const string::secure_string &iv,
                      const string::secure_string &clear_text,
                      std::function<void(const string::secure_string &cipher_text)> &&success_callback,
                      std::function<void(const string::secure_string &error_message)> &&
                      failure_callback) {
        AesBase::encrypt(key, iv, clear_text, std::move(success_callback), std::move(failure_callback));
    }

    string::secure_string Aes::encrypt(const string::secure_string &key,
                                       const string::secure_string &iv,
                                       const string::secure_string &clear_text) {
        std::promise<int> promise;
        string::secure_string cipher_string;
        string::secure_string error_string;
        auto future = promise.get_future();

        encrypt(key, iv, clear_text, [&promise, &cipher_string](const string::secure_string &cipher_text) {
                             cipher_string = string::secure_string{cipher_text};
                             promise.set_value(0);
                         }, [&promise, &error_string](const string::secure_string &error_message) {
                             error_string = error_message;
                             promise.set_value(1);
                         });

        if (future.get()) {
            throw std::runtime_error(std::string{error_string});
        }

        return std::move(cipher_string);
    }

    void Aes::decrypt(const string::secure_string &key,
                      const string::secure_string &iv,
                      const string::secure_string &cipher_text,
                      std::function<void(const string::secure_string &clear_text)> &&success_callback,
                      std::function<void(const string::secure_string &error_message)> &&
                      failure_callback) {
        AesBase::decrypt(key, iv, cipher_text, std::move(success_callback), std::move(failure_callback));
    }

    string::secure_string Aes::decrypt(const string::secure_string &key, const string::secure_string &iv,
                                       const string::secure_string &cipher_text) {
        std::promise<int> promise;
        string::secure_string result;
        string::secure_string error_string;
        auto future = promise.get_future();

        decrypt(key, iv, cipher_text, [&promise, &result](const string::secure_string &clear_text) {
                             result = string::secure_string{clear_text};
                             promise.set_value(0);
                         }, [&promise, &error_string](const string::secure_string &error_message) {
                             error_string = error_message;
                             promise.set_value(1);
                         });

        if (future.get()) {
            throw std::runtime_error(std::string{error_string});
        }

        return std::move(result);
    }

    void Aes::sign(const string::secure_string &key,
                   const string::secure_string &clear_text,
                   std::function<void(const string::secure_string &signature)> &&success_callback,
                   std::function<void(
                       const string::secure_string &error_message)> &&failure_callback) {
        AesBase::sign(key, clear_text, std::move(success_callback), std::move(failure_callback));
    }

    string::secure_string Aes::sign(const string::secure_string &key, const string::secure_string &clear_text) {
        std::promise<int> promise;
        string::secure_string result;
        string::secure_string error_string;
        auto future = promise.get_future();

        AesBase::sign(key, clear_text, [&promise, &result](const string::secure_string &signature) {
                          result = string::secure_string{signature};
                          promise.set_value(0);
                      }, [&promise, &error_string](const string::secure_string &error_message) {
                          error_string = error_message;
                          promise.set_value(1);
                      });

        if (future.get()) {
            throw std::runtime_error(std::string{error_string});
        }

        return std::move(result);
    }

    void Aes::verify(const string::secure_string &key,
                     const string::secure_string &clear_text,
                     const string::secure_string &signature,
                     std::function<void()> &&success_callback,
                     std::function<void(const string::secure_string &error_message)> &&
                     failure_callback) {
        AesBase::verify(key, clear_text, signature, std::move(success_callback), std::move(failure_callback));
    }

    bool Aes::verify(const string::secure_string &key, const string::secure_string &clear_text,
                     const string::secure_string &signature) {
        std::promise<int> promise;
        bool result;
        string::secure_string error_string;
        auto future = promise.get_future();

        verify(key, clear_text, signature, [&promise, &result]() {
                            result = true;
                            promise.set_value(0);
                        }, [&promise, &error_string](const string::secure_string &error_message) {
                            error_string = error_message;
                            promise.set_value(1);
                        });

        if (future.get()) {
            throw std::runtime_error(std::string{error_string});
        }

        return result;
    }

    int Aes::run() {
        try {
            if (!encrypt_secret_.empty() && !init_vector_.empty() && !input_.empty()) {
                std::cout << encrypt(string::secure_string{encrypt_secret_}, string::secure_string{init_vector_},
                                     string::secure_string{input_});
                return 0;
            }

            if (!decrypt_secret_.empty() && !init_vector_.empty() && !input_.empty()) {
                std::cout << decrypt(string::secure_string{decrypt_secret_}, string::secure_string{init_vector_},
                                     string::secure_string{input_});
                return 0;
            }

            if (!signature_secret_.empty() && !input_.empty()) {
                std::cout << sign(string::secure_string{signature_secret_}, string::secure_string{input_});
                return 0;
            }

            if (!verify_secret_.empty() && !input_.empty() && !signature_.empty()) {
                std::cout << verify(string::secure_string{verify_secret_}, string::secure_string{input_},
                                    string::secure_string{signature_});
                return 0;
            }
        } catch (const std::exception &ex) {
            std::cerr << ex.what();
            return 1;
        }

        return 1;
    }
}

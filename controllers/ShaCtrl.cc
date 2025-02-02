/**
* @copyright Copyright (C) 2025, Ereyna Labs Ltd. - All Rights Reserved
 * @file ShaCtrl.cc
 * @parblock
 * This file is subject to the terms and conditions defined in file 'LICENSE.md',
 * which is part of this source code package.  Proprietary and confidential.
 * @endparblock
 * @author Dave Linten <david@ereynalabs.com>
 */

#include "ShaCtrl.h"

#include <future>

namespace encryptopp {
    void Sha::sha1_hash(const string::secure_string& clear_text,
                            std::function<void(const string::secure_string& cipher_text)>&& success_callback,
                            std::function<void(const string::secure_string& error_message)>&& failure_callback) {
        ShaBase::sha1_hash(clear_text,
                               [success_callback](const string::secure_string& cipher_text) {
                                   (success_callback)(cipher_text);
                               }, [failure_callback](const string::secure_string& error_message) {
                                   (failure_callback)(error_message);
                               });
    }

    string::secure_string Sha::sha1_hash(const string::secure_string& clear_text) {
        std::promise<int> promise;
        std::future<int> future = promise.get_future();
        string::secure_string error_string;
        string::secure_string result;

        sha1_hash(clear_text, [&promise, &result](const string::secure_string &cipher_text) {
                     result = cipher_text;
                     promise.set_value(0);
                 }, [&promise, &error_string](const string::secure_string &error_message) {
                     error_string = error_message;
                     promise.set_value(1);
                 });

        if(future.get()) {
            throw std::runtime_error(error_string.c_str());
        }

        return std::move(result);
    }

    void Sha::sha256_hash(const string::secure_string& clear_text,
                              std::function<void(const string::secure_string& cipher_text)>&& success_callback,
                              std::function<void(const string::secure_string& error_message)>&& failure_callback) {
        ShaBase::sha256_hash(clear_text,
                                 [success_callback](const string::secure_string& cipher_text) {
                                     (success_callback)(cipher_text);
                                 }, [failure_callback](const string::secure_string& error_message) {
                                     (failure_callback)(error_message);
                                 });
    }

    string::secure_string Sha::sha256_hash(const string::secure_string& clear_text) {
        std::promise<int> promise;
        std::future<int> future = promise.get_future();
        string::secure_string error_string;
        string::secure_string result;

        sha256_hash(clear_text, [&promise, &result](const string::secure_string &cipher_text) {
                     result = cipher_text;
                     promise.set_value(0);
                 }, [&promise, &error_string](const string::secure_string &error_message) {
                     error_string = error_message;
                     promise.set_value(1);
                 });

        if(future.get()) {
            throw std::runtime_error(error_string.c_str());
        }

        return std::move(result);
    }

    void Sha::sha512_hash(const string::secure_string& clear_text,
                              std::function<void(const string::secure_string& cipher_text)>&& success_callback,
                              std::function<void(const string::secure_string& error_message)>&& failure_callback) {
        ShaBase::sha512_hash(clear_text,
                                 [success_callback](const string::secure_string& cipher_text) {
                                     (success_callback)(cipher_text);
                                 }, [failure_callback](const string::secure_string& error_message) {
                                     (failure_callback)(error_message);
                                 });
    }

    string::secure_string Sha::sha512_hash(const string::secure_string& clear_text) {
        std::promise<int> promise;
        std::future<int> future = promise.get_future();
        string::secure_string error_string;
        string::secure_string result;

        sha512_hash(clear_text, [&promise, &result](const string::secure_string &cipher_text) {
                     result = cipher_text;
                     promise.set_value(0);
                 }, [&promise, &error_string](const string::secure_string &error_message) {
                     error_string = error_message;
                     promise.set_value(1);
                 });

        if(future.get()) {
            throw std::runtime_error(error_string.c_str());
        }

        return std::move(result);
    }

    int Sha::run() {
        try {
            switch (algo_) {
                case sha1:
                    std::cout << sha1_hash(string::secure_string { input_ });
                break;
                case sha256:
                    std::cout << sha256_hash(string::secure_string { input_ });
                break;
                case sha512:
                    std::cout << sha512_hash(string::secure_string { input_ });
                break;
                default:
                    throw std::runtime_error ("Unknown algorithm type.");
            }
        } catch(const std::exception &ex) {
            std::cerr << ex.what();
            return 1;
        }

        return 0;
    }
}


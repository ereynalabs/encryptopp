/**
 * @copyright Copyright (C) 2024, Ereyna Labs Ltd. - All Rights Reserved
 * @file JwtCtrl.cc
 * @parblock
 * This file is subject to the terms and conditions defined in file 'LICENSE.md',
 * which is part of this source code package.  Proprietary and confidential.
 * @endparblock
 * @author Dave Linten <david@ereynalabs.com>
 */

#include "JwtCtrl.h"

#include <future>

namespace encryptopp {
    void Jwt::encode(const models::JwtPayload &payload, const string::secure_string &secret,
                         std::function<void(const string::secure_string &encoded_text)> &&success_callback,
                         std::function<void(const string::secure_string &error_message)> &&failure_callback) {
        JwtBase::encode(payload, secret, std::move(success_callback), std::move(failure_callback));
    }

    string::secure_string Jwt::encode(const models::JwtPayload &payload, const string::secure_string &secret) {
        std::promise<int> promise;
        std::future<int> future = promise.get_future();
        string::secure_string result;
        string::secure_string error_string;

        encode(payload, secret, [&promise, &result](const string::secure_string &token) {
                   result = token;
                   promise.set_value(0);
               }, [&promise, &error_string](const string::secure_string &error_message) {
                   error_string = error_message;
                   promise.set_value(1);
               });

        if (future.get()) {
            throw std::runtime_error(error_string.c_str());
        }

        return result;
    }

    void Jwt::decode(const string::secure_string &token, const string::secure_string &secret,
                         std::function<void(const models::JwtPayload &payload)> &&success_callback,
                         std::function<void(const string::secure_string &error_message)> &&failure_callback) {
        JwtBase::decode(token, secret, std::move(success_callback), std::move(failure_callback));
    }

    models::JwtPayload Jwt::decode(const string::secure_string &token, const string::secure_string &secret) {
        std::promise<int> promise;
        std::future<int> future = promise.get_future();
        models::JwtPayload result;
        string::secure_string error_string;

        decode(token, secret, [&promise, &result](const models::JwtPayload &payload) {
                   result = payload;
                   promise.set_value(0);
               }, [&promise, &error_string](const string::secure_string &error_message) {
                   error_string = error_message;
                   promise.set_value(1);
               });

        if (future.get()) {
            throw std::runtime_error(error_string.c_str());
        }

        return result;
    }

    int Jwt::run() {
        try {
            if (decode_) {
                std::cout << decode(string::secure_string{input_}, string::secure_string{secret_}).toString();
                return 0;
            }

            if (encode_) {
                try {
                    Json::Value root;
                    Json::Reader reader;
                    if (const bool parsing_successful = reader.parse(input_, root); !parsing_successful) {
                        std::cerr << "Failed to parse " + reader.getFormattedErrorMessages();
                        return 1;
                    }

                    std::cout << encode(models::JwtPayload{root}, string::secure_string{secret_});
                    return 0;
                } catch (std::exception &ex) {
                    throw std::runtime_error(ex.what());
                }
            }
        } catch (std::exception &ex) {
            std::cerr << ex.what();
        }

        return 1;
    }
}

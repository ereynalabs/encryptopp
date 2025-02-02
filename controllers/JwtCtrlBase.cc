/**
 * @copyright Copyright (C) 2024, Ereyna Labs Ltd. - All Rights Reserved
 * @file JwtCtrlBase.cc
 * @parblock
 * This file is subject to the terms and conditions defined in file 'LICENSE.md',
 * which is part of this source code package.  Proprietary and confidential.
 * @endparblock
 * @author Dave Linten <david@ereynalabs.com>
 */

#include "JwtCtrlBase.h"

#include <string>
#include <iomanip>
#include <sstream>
#include "Base64Ctrl.h"

namespace encryptopp {

    void JwtBase::encode(const models::JwtPayload &payload, const string::secure_string &secret,
                             std::function<void(const string::secure_string &token)> &&success_callback,
                             std::function<void(const string::secure_string &error_message)> &&failure_callback) {
        try {
            Base64 base64;
            const string::secure_string header = R"({"alg":"HS256","typ":"JWT"})";
            const string::secure_string encoded_header = base64.encode(header, false, true);
            const string::secure_string encoded_payload = base64.encode(
                string::secure_string{payload.toString()}, false, true);

            string::secure_string data = encoded_header + "." + encoded_payload;

            AesBase::sign(secret, data, [data, success_callback](const string::secure_string &signature) {
                (success_callback)(data + "." + signature);
            }, std::move(failure_callback));
        } catch (std::exception &ex) {
            (failure_callback)(ex.what());
        }
    }

    void JwtBase::decode(const string::secure_string &token, const string::secure_string &secret,
                             std::function<void(const models::JwtPayload &payload)> &&success_callback,
                             std::function<void(const string::secure_string &error_message)> &&failure_callback) {
        try {
            std::size_t first_dot = token.find('.');
            std::size_t second_dot = token.find('.', first_dot + 1);
            Base64 base64;

            if (first_dot == string::secure_string::npos || second_dot == string::secure_string::npos)
                throw std::runtime_error("Invalid JWT token");

            string::secure_string encoded_payload = token.substr(first_dot + 1, second_dot - first_dot - 1);

            string::secure_string payload = base64.decode(encoded_payload);

            Json::Value root;
            Json::CharReaderBuilder builder;
            std::istringstream payload_stream(payload);
            std::string errs;
            if (!Json::parseFromStream(builder, payload_stream, &root, &errs)) {
                (failure_callback)(string::secure_string { "Failed to parse payload JSON: " + errs });
                return;
            }

            string::secure_string encoded_signature = token.substr(second_dot + 1);
            string::secure_string data = token.substr(0, second_dot);

            AesBase::verify(secret, data, encoded_signature, [root, success_callback]() {
                                    (success_callback)(models::JwtPayload{root});
                                }, [failure_callback](const string::secure_string &error_message) {
                                    (failure_callback)(error_message);
                                });
        } catch (std::exception &ex) {
            (failure_callback)(ex.what());
        }
    }
}

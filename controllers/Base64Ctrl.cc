/**
* @copyright Copyright (C) 2025, Ereyna Labs Ltd. - All Rights Reserved
 * @file Base64Ctrl.cc
 * @parblock
 * This file is subject to the terms and conditions defined in file 'LICENSE.md',
 * which is part of this source code package.  Proprietary and confidential.
 * @endparblock
 * @author Dave Linten <david@ereynalabs.com>
 */

#include "Base64Ctrl.h"

#include <future>

namespace encryptopp {
    void Base64::encode(const string::secure_string& clear_text,
                            std::function<void(const string::secure_string& encoded_text)>&& success_callback,
                            std::function<void(const string::secure_string& error_message)>&& failure_callback,
                            const bool padded, const bool url) {
        Base64Base::encode(clear_text,
                               [success_callback](const string::secure_string& encoded_text) {
                                   const auto& temp_cipher_text = std::string{encoded_text};
                                   (success_callback)(encoded_text);
                               }, [failure_callback](const string::secure_string& error_message) {
                                   const auto& temp_error_message = std::string{error_message};
                                   (failure_callback)(error_message);
                               }, padded, url);
    }

    void Base64::decode(const string::secure_string& encoded_text,
                            std::function<void(const string::secure_string& clear_text)>&& success_callback,
                            std::function<void(const string::secure_string& error_message)>&& failure_callback) {
        Base64Base::decode(encoded_text, std::move(success_callback), std::move(failure_callback));
    }

    string::secure_string Base64::encode(const string::secure_string& clear_text, bool padded, bool url) {
        string::secure_string return_text;

        std::promise<int> promise;
        std::future<int> future = promise.get_future();

        encode(clear_text, [&promise, &return_text](const string::secure_string& encoded_text) {
            return_text = std::string{ encoded_text };
            promise.set_value(0);
        }, [&promise](const string::secure_string& error_message) {
            promise.set_value(1);
        }, padded, url);

        future.get();
        return return_text;
    }

    string::secure_string Base64::decode(const string::secure_string& encoded_text) {
        string::secure_string return_text;

        std::promise<int> promise;
        std::future<int> future = promise.get_future();

        decode(encoded_text, [&promise, &return_text](const string::secure_string& decoded_text) {
            return_text = std::string{decoded_text};
            promise.set_value(0);
        }, [&promise](const string::secure_string& error_message) {
            promise.set_value(1);
        });

        future.get();
        return return_text;
    }

    int Base64::run() {
        try {
            if (decode_) {
                std::cout << decode(string::secure_string { input_ });
                return 0;
            }
            std::cout << encode(string::secure_string { input_ }, padded_, url_);
            return 0;
        } catch (const std::exception &ex) {
            std::cerr << ex.what();
            return 1;
        }
    }
}

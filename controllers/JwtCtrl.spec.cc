/**
 * @copyright Copyright (C) 2025, Ereyna Labs Ltd. - All Rights Reserved
 * @file JwtCtrl.spec.cc
 * @parblock
 * This file is subject to the terms and conditions defined in file 'LICENSE.md',
 * which is part of this source code package.  Proprietary and confidential.
 * @endparblock
 * @author Dave Linten <david@ereynalabs.com>
 */

#include <gtest/gtest.h>
#include <JwtCtrl.h>
#include "secure_string.h"
#include <encryptopp.h>

/**
 * WARNING: Implementations of secure_string CANNOT be debugged.  I.e. It is a PROPER secure_string that actively
 *          prevents peeking, and therefore resolution of variables using it will crash the software and PID.
 */
using namespace encryptopp;

namespace {
    const string::secure_string secret {"my_fancy_secret"};

}

TEST(Jwt, EncodeDecodeAsync) {
    auto controller = Jwt{};

    models::JwtPayload random_data;

    controller.encode(random_data, secret,
                      [random_data, &controller](
                  const string::secure_string& token) {
                          std::cout << token << std::endl;
                          controller.decode(token, secret,
                                            [random_data](const models::JwtPayload& payload) {
                                                EXPECT_STREQ(random_data.toJson().toStyledString().c_str(), payload.toJson().toStyledString().c_str());
                                            }, [](const string::secure_string& error_message) {
                                                EXPECT_TRUE(false) << error_message;
                                            });
                      }, [](const string::secure_string& error_message) {
                          //EXPECT_TRUE(true);
                          EXPECT_TRUE(false) << error_message;
                      });
}

TEST(Jwt, EncodeDecode) {
    auto controller = Jwt{};

    const models::JwtPayload random_data;

    const auto& token = controller.encode(random_data, secret);
    const auto& payload = controller.decode(token, secret);
    EXPECT_STREQ(random_data.toString().c_str(), payload.toString().c_str());

}

TEST(Jwt, EncodeDecodeInvalidSignatureAsync) {
    auto controller = Jwt{};

    models::JwtPayload random_data;

    auto datetime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    std::cout << datetime << std::endl;

    random_data.setExpNow();
    random_data.setIatNow();
    random_data.setNbfNow();

    controller.encode(random_data, secret,
                      [random_data, &controller](
                  const string::secure_string& token) {
                          std::cout << token << std::endl;
                          string::secure_string tmp_token { token };
                          tmp_token.resize(token.length() - 1);

                          controller.decode(tmp_token, secret,
                                            [random_data](const models::JwtPayload& payload) {
                                                EXPECT_TRUE(false) << payload.toString();
                                            }, [](const string::secure_string& error_message) {
                                                EXPECT_STREQ(error_message.c_str(), "The signature is incorrect for the data supplied");
                                            });
                      }, [](const string::secure_string& error_message) {
                          EXPECT_TRUE(false) << error_message;
                      });
}

TEST(Jwt, EncodeDecodeInvalidSignature) {
    auto controller = Jwt{};

    models::JwtPayload random_data;

    const auto datetime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    std::cout << datetime << std::endl;

    random_data.setExpNow();
    random_data.setIatNow();
    random_data.setNbfNow();

    const auto& token = controller.encode(random_data, secret);
    string::secure_string tmp_token { token };
    tmp_token.resize(token.length() - 1);

    try {
        const auto& payload = controller.decode(tmp_token, secret);
    } catch (const std::exception &ex) {
        EXPECT_STREQ(ex.what(), "The signature is incorrect for the data supplied");
    }

}
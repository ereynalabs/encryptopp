/**
* @copyright Copyright (C) 2024, Ereyna Labs Ltd. - All Rights Reserved
 * @file ShaCtrl.spec.cc
 * @parblock
 * This file is subject to the terms and conditions defined in file 'LICENSE.md',
 * which is part of this source code package.  Proprietary and confidential.
 * @endparblock
 * @author Dave Linten <david@ereynalabs.com>
 */

#include <gtest/gtest.h>
#include <ShaCtrl.h>
#include "secure_string.h"
#include <encryptopp.h>

/**
 * WARNING: Implementations of secure_string CANNOT be debugged.  I.e. It is a PROPER secure_string that actively
 *          prevents peeking, and therefore resolution of variables using it will crash the software and PID.
 */
using namespace encryptopp;

constexpr int data_size = 4096;

const std::string test_sha_data = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor "
        "incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis "
        "nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. "
        "Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu "
        "fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in "
        "culpa qui officia deserunt mollit anim id est laborum.";

const std::string test_sha1_result = "cd36b370758a259b34845084a6cc38473cb95e27";
const std::string test_sha256_result = "2d8c2f6d978ca21712b5f6de36c9d31fa8e96a4fa5d8ff8b0188dfb9e7c171bb";
const std::string test_sha512_result = "8ba760cac29cb2b2ce66858ead169174057aa1298ccd581514e6db6dee3285280"
        "ee6e3a54c9319071dc8165ff061d77783100d449c937ff1fb4cd1bb516a69b9";

TEST(Sha, Sha1HashAsync) {
    auto controller = Sha{};
    string::secure_string input_text{test_sha_data};
    controller.sha1_hash(input_text,
                      [](const string::secure_string& cipher_text) {
                          EXPECT_STREQ(test_sha1_result.c_str(), cipher_text.c_str());
                      }, [](const string::secure_string& error_message) {
                          EXPECT_TRUE(false) << error_message;
                      });
}

TEST(Sha, Sha1Hash) {
    try {
        auto controller = Sha{};
        string::secure_string input_text{test_sha_data};
        const auto& cipher_text = controller.sha1_hash(input_text);
        EXPECT_STREQ(test_sha1_result.c_str(), cipher_text.c_str());
    } catch(std::exception &ex) {
        EXPECT_TRUE(false) << ex.what();
    }
}

TEST(Sha, Sha256HashAsync) {
    auto controller = Sha{};
    string::secure_string input_text{test_sha_data};
    controller.sha256_hash(input_text,
                      [](const string::secure_string& cipher_text) {
                          EXPECT_STREQ(test_sha256_result.c_str(), cipher_text.c_str());
                      }, [](const string::secure_string& error_message) {
                          EXPECT_TRUE(false) << error_message;
                      });
}

TEST(Sha, Sha256Hash) {
    try {
        auto controller = Sha{};
        string::secure_string input_text{test_sha_data};
        const auto& cipher_text = controller.sha256_hash(input_text);
        EXPECT_STREQ(test_sha256_result.c_str(), cipher_text.c_str());
    } catch(std::exception &ex) {
        EXPECT_TRUE(false) << ex.what();
    }
}

TEST(Sha, Sha512HashAsync) {
    auto controller = Sha{};
    string::secure_string input_text{test_sha_data};
    controller.sha512_hash(input_text,
                      [](const string::secure_string& cipher_text) {
                          EXPECT_STREQ(test_sha512_result.c_str(), cipher_text.c_str());
                      }, [](const string::secure_string& error_message) {
                          EXPECT_TRUE(false) << error_message;
                      });
}

TEST(Sha, Sha512Hash) {
    try {
        auto controller = Sha{};
        string::secure_string input_text{test_sha_data};
        const auto& cipher_text = controller.sha512_hash(input_text);
        EXPECT_STREQ(test_sha512_result.c_str(), cipher_text.c_str());
    } catch(std::exception &ex) {
        EXPECT_TRUE(false) << ex.what();
    }
}

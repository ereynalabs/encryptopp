/**
 * @copyright Copyright (C) 2025, Ereyna Labs Ltd. - All Rights Reserved
 * @file AesCtrl.spec.cc
 * @parblock
 * This file is subject to the terms and conditions defined in file 'LICENSE.md',
 * which is part of this source code package.  Proprietary and confidential.
 * @endparblock
 * @author Dave Linten <david@ereynalabs.com>
 */

#include <gtest/gtest.h>
#include <AesCtrl.h>
#include "secure_string.h"
#include <encryptopp.h>

/**
 * WARNING: Implementations of secure_string CANNOT be debugged.  I.e. It is a PROPER secure_string that actively
 *          prevents peeking, and therefore resolution of variables using it will crash the software and PID.
 */
using namespace encryptopp;

namespace {
    constexpr int data_size = 32;
}

TEST(Aes, EncryptDecryptAlphaAsync) {
    auto controller = Aes{};

    string::secure_string random_data;

    for (int count = 0; count < 10; ++count) {
        string::secure_string random_key = "test key";
        string::secure_string random_iv = "test iv";

        for (int idx = 0; idx < data_size; ++idx) {
            random_key.push_back(rand() % 26 + 'a');
            random_iv.push_back(rand() % 26 + 'a');
            random_data.push_back(rand() % 26 + 'a');

            controller.encrypt(random_key, random_iv, random_data,
                               [random_key, random_iv, random_data, &controller](
                           const string::secure_string& cipher_text) {
                                   controller.decrypt(random_key, random_iv, cipher_text,
                                                      [random_data](const string::secure_string& plain_text) {
                                                          EXPECT_STREQ(random_data.c_str(), plain_text.c_str());
                                                      }, [](const string::secure_string& error_message) {
                                                          //EXPECT_TRUE(true);
                                                          EXPECT_TRUE(false) << error_message;
                                                      });
                               }, [](const string::secure_string& error_message) {
                                   EXPECT_TRUE(false) << error_message;
                               });
        }
    }
}

TEST(Aes, EncryptDecryptAlpha) {
    auto controller = Aes{};

    string::secure_string random_data;

    for (int count = 0; count < 10; ++count) {
        string::secure_string random_key = "test key";
        string::secure_string random_iv = "test iv";

        for (int idx = 0; idx < data_size; ++idx) {
            random_key.push_back(rand() % 26 + 'a');
            random_iv.push_back(rand() % 26 + 'a');
            random_data.push_back(rand() % 26 + 'a');

            const auto& cipher_text = controller.encrypt(random_key, random_iv, random_data);
            const auto& clear_text = controller.decrypt(random_key, random_iv, cipher_text);
            EXPECT_STREQ(clear_text.c_str(), random_data.c_str());
        }
    }
}

TEST(Aes, EncryptDecryptAsciiAsync) {
    auto controller = Aes{};

    string::secure_string random_data;

    for (int count = 0; count < 10; ++count) {
        string::secure_string random_key = "test key";
        string::secure_string random_iv = "test iv";

        for (int idx = 0; idx < data_size; ++idx) {
            random_key.push_back(rand() % 93 + '!');
            random_iv.push_back(rand() % 93 + '!');
            random_data.push_back(rand() % 93 + '!');

            controller.encrypt(random_key, random_iv, random_data,
                               [random_key, random_iv, random_data, &controller](
                           const string::secure_string& cipher_text) {
                                   controller.decrypt(random_key, random_iv, cipher_text,
                                                      [random_data](const string::secure_string& plain_text) {
                                                          EXPECT_STREQ(random_data.c_str(), plain_text.c_str());
                                                      }, [](const string::secure_string& error_message) {
                                                          //EXPECT_TRUE(true);
                                                          EXPECT_TRUE(false) << error_message;
                                                      });
                               }, [](const string::secure_string& error_message) {
                                   EXPECT_TRUE(false) << error_message;
                               });
        }
    }
}

TEST(Aes, EncryptDecryptAscii) {
    auto controller = Aes{};

    string::secure_string random_data;

    for (int count = 0; count < 10; ++count) {
        string::secure_string random_key = "test key";
        string::secure_string random_iv = "test iv";

        for (int idx = 0; idx < data_size; ++idx) {
            random_key.push_back(rand() % 93 + '!');
            random_iv.push_back(rand() % 93 + '!');
            random_data.push_back(rand() % 93 + '!');

            const auto& cipher_text = controller.encrypt(random_key, random_iv, random_data);
            const auto& clear_text = controller.decrypt(random_key, random_iv, cipher_text);
            EXPECT_STREQ(clear_text.c_str(), random_data.c_str());
        }
    }
}

TEST(Aes, EncryptDecryptUtf8Async) {
    auto controller = Aes{};

    string::secure_string random_data;

    for (int count = 0; count < 10; ++count) {
        string::secure_string random_key = "test key";
        string::secure_string random_iv = "test iv";

        for (int idx = 0; idx < data_size; ++idx) {
            random_key.push_back(rand() % 127 + '(');
            random_iv.push_back(rand() % 127 + '(');
            random_data.push_back(rand() % 127 + '(');

            controller.encrypt(random_key, random_iv, random_data,
                               [random_key, random_iv, random_data, &controller](
                           const string::secure_string& cipher_text) {
                                   controller.decrypt(random_key, random_iv, cipher_text,
                                                      [random_data](const string::secure_string& plain_text) {
                                                          EXPECT_STREQ(random_data.c_str(), plain_text.c_str());
                                                      }, [](const string::secure_string& error_message) {
                                                          //EXPECT_TRUE(true);
                                                          EXPECT_TRUE(false) << error_message;
                                                      });
                               }, [](const string::secure_string& error_message) {
                                   EXPECT_TRUE(false) << error_message;
                               });
        }
    }
}

TEST(Aes, EncryptDecryptUtf8) {
    auto controller = Aes{};

    string::secure_string random_data;

    for (int count = 0; count < 10; ++count) {
        string::secure_string random_key = "test key";
        string::secure_string random_iv = "test iv";

        for (int idx = 0; idx < data_size; ++idx) {
            random_key.push_back(rand() % 127 + '(');
            random_iv.push_back(rand() % 127 + '(');
            random_data.push_back(rand() % 127 + '(');

            const auto& cipher_text = controller.encrypt(random_key, random_iv, random_data);
            const auto& clear_text = controller.decrypt(random_key, random_iv, cipher_text);
            EXPECT_STREQ(clear_text.c_str(), random_data.c_str());
        }
    }
}

TEST(Aes, SignVerifyAsync) {
    auto controller = Aes{};
    const string::secure_string& test_key{"my_secret_key"};
    string::secure_string test_data = "some data";

    controller.sign(test_key, test_data, [&controller, test_key, test_data](const string::secure_string& signature) {
                        EXPECT_FALSE(signature.empty());
                        controller.verify(test_key, test_data, signature, []() {
                                              EXPECT_TRUE(true);
                                          }, [](const string::secure_string& error_message) {
                                              EXPECT_TRUE(false) << error_message;
                                          });
                    }, [](const string::secure_string& error_message) {
                        EXPECT_TRUE(false) << error_message;
                    });
}


TEST(Aes, SignVerify) {
    auto controller = Aes{};
    const string::secure_string& test_key{"my_secret_key"};
    const string::secure_string& test_data = "some data";

    const auto& signature = controller.sign(test_key, test_data);
    bool valid = controller.verify(test_key, test_data, signature);
    EXPECT_TRUE(valid);
}

// TEST(Aes, EncryptDecryptLibraryCall) {
//     std::string random_key = "test key";
//     std::string random_iv = "test iv";
//     std::string random_data = "Hello";
//
//     aes_encrypt(random_key, random_iv, random_data,
//                              [random_key, random_iv, random_data](
//                          const std::string& cipher_text) {
//                                  aes_decrypt(random_key, random_iv, cipher_text,
//                                                           [random_data](const std::string& plain_text) {
//                                                               EXPECT_STREQ(random_data.c_str(), plain_text.c_str());
//                                                           }, [](const std::string& error_message) {
//                                                               //EXPECT_TRUE(true);
//                                                               EXPECT_TRUE(false) << error_message;
//                                                           });
//                              }, [](const std::string& error_message) {
//                                  EXPECT_TRUE(false) << error_message;
//                              });
// }
//
// TEST(Aes, SignVerifyLibraryCall) {
//     const std::string& test_key{"my_secret_key"};
//     std::string test_data = "some data";
//
//     aes_sign(test_key, test_data, [test_key, test_data](const std::string& signature) {
//                               EXPECT_FALSE(signature.empty());
//                               aes_verify(test_key, test_data, signature, []() {
//                                                           EXPECT_TRUE(true);
//                                                       }, [](const std::string& error_message) {
//                                                           EXPECT_TRUE(false) << error_message;
//                                                       });
//                           }, [](const std::string& error_message) {
//                               EXPECT_TRUE(false) << error_message;
//                           });
// }

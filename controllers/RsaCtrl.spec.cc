/**
* @copyright Copyright (C) 2025, Ereyna Labs Ltd. - All Rights Reserved
 * @file RsaCtrl.spec.cc
 * @parblock
 * This file is subject to the terms and conditions defined in file 'LICENSE.md',
 * which is part of this source code package.  Proprietary and confidential.
 * @endparblock
 * @author Dave Linten <david@ereynalabs.com>
 */

#include <gtest/gtest.h>
#include <RsaCtrl.h>
#include "secure_string.h"
#include <encryptopp.h>

#include <jwt-cpp/jwt.h>

using namespace encryptopp;

namespace {
    const string::secure_string test_private_key = "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEogIBAAKCAQEAuyU0ABQ5+NTwp3UjnS1GGSotHISgJT6e6m3IQtNiyw3yTnSG\n"
            "ASQDUK5ms22FhF4lZ6z1EbK2BbkQKkBkD7OzMHMA/W/Wlk+p4n3J1zPICLcQemn9\n"
            "OoS09EBSPWXRaEXJrFipXfstHY0PP3+qQZCqIGM0Id8mATH36/w+WzHZUd1mw374\n"
            "pj2XKBP5/FEuTVT/fKjJpBNYCTo4sMVgB7etycvb6EKgtKdl2MV+K5ADXu/yVBCn\n"
            "wwz56TqwAXLUIb1Ls5Q5X6sUfkxJAVLUX7RCbQ+sJUawGwrd7UpyeYFla6y+6WKM\n"
            "DqNMs2apSxfxej8yFe/WU5TmA2aVz9iSM+UAEQIDAQABAoIBACbR7Ev55h6eOT9b\n"
            "VqRjgE93Br2MK1Yee8OAO1LVW4BoZ7Nri2KQMFnbm3Uryk7vYo3zfDCMJCLixR4m\n"
            "ljsFmS17JaDswpQSeViApE5OMPfR1Yq3Eq7BWXHzJ7wRs1MQaumjyJo0oKKpIJkY\n"
            "593K3udx/J3sFouX7GgYvmyXVg+bZUYlCdio1YpshNQyQh9gOtujEwE6ELpIYFd7\n"
            "fMI3PTLvhEk1JI3oW/Ux44ee3rIKxJnjlCggRrsU5PzkS140nMFjavflOjlz93Gn\n"
            "IUfiKiaVf4BFpGWHtMZaYuU2PXU57uJTmJ4oKR4rCjHiCv75aTxfdSQnCz/W8zVf\n"
            "XtkEHhsCgYEA3TQt1o5U/FEW1zPbNEps/23++Oix6K+0kqNzeUl5/09xFa+OEn1d\n"
            "CWQ1rEsT7BKZtY5cdbxC+siIJxKjzwB8r86qOOhnuIj9uWc0jLoFBfZ2kkLAEe3L\n"
            "LpujiqgmFyla9tSbdDGAyNlvDGGmZgDtxqmFVex/9tlfbdTiNW7QNzcCgYEA2JV/\n"
            "QDXH5DERBE0AkV05I6Qn2XuWultk0G8mpEPuxXByAfzB98ER9uN2F54sOOAzH8Ai\n"
            "yjThKV5gX5CZvekWv4D+JPk7ZDGGePliNufzzLvArFRgUlJYHM1XYH7Oyz3z4yye\n"
            "SYRLLPyRBgAj1yMZ9TvgBseWgPdsxwzjW4xHFvcCgYAZj48AbQALC/+8rGRXHYaM\n"
            "2ZQOBS2RusP98d9FE6WCSBbEL74WCuB2VlsRZreNnvSeEy5B+JgwzH1XLoM5R1Ah\n"
            "LJtk6g4aN9JB21gqLtCnyLwY2JfDOpww7ZEvU5DbOk8lmJnCCnpcOyvm3V3SCadw\n"
            "PmSG8kYzKxko4uGk1QJAbwKBgBKRxsZHlirfdhkLTRgpiQOgSHZiHUs/GMayMPr2\n"
            "hBtTh8LZ2/uVByhG2lIuEpaRynBXdeQmYoO8fsDS0guxV2z171RWNhxiDqiCoUQZ\n"
            "4RJVqrBbz6JfQwS9Klewp6RPXIDGy498E0H5Kan9CxWgAdK/3nZWWHYYQLBUT44C\n"
            "2fmDAoGATUyeYiIqx70HOIMQ17DyNTScmwLLchnqLgiorDDCO2I4lLsqlqJ7Iiqk\n"
            "dHniOcPRPxLAS0ZiXMkKuaxL5gt5vdjsq5QuJa7JtLpQ6o8r0YVOZmTgLoYRX872\n"
            "zU6Yro9m0DyrXX0/fjHYYLoNaAybxDvAc6yJ5JeO5m5RhtLAhhA=\n"
            "-----END RSA PRIVATE KEY-----\n";

    const string::secure_string test_public_key = "-----BEGIN PUBLIC KEY-----\n"
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuyU0ABQ5+NTwp3UjnS1G\n"
            "GSotHISgJT6e6m3IQtNiyw3yTnSGASQDUK5ms22FhF4lZ6z1EbK2BbkQKkBkD7Oz\n"
            "MHMA/W/Wlk+p4n3J1zPICLcQemn9OoS09EBSPWXRaEXJrFipXfstHY0PP3+qQZCq\n"
            "IGM0Id8mATH36/w+WzHZUd1mw374pj2XKBP5/FEuTVT/fKjJpBNYCTo4sMVgB7et\n"
            "ycvb6EKgtKdl2MV+K5ADXu/yVBCnwwz56TqwAXLUIb1Ls5Q5X6sUfkxJAVLUX7RC\n"
            "bQ+sJUawGwrd7UpyeYFla6y+6WKMDqNMs2apSxfxej8yFe/WU5TmA2aVz9iSM+UA\n"
            "EQIDAQAB\n"
            "-----END PUBLIC KEY-----\n";
}

TEST(Rsa, GenerateKeyPairAsync) {
    auto controller = Rsa{};

    controller.generate_keypair([](const string::secure_string &private_key,
                                   const string::secure_string &public_key) {
                                    EXPECT_STREQ(private_key.substr(0,27).c_str(), "-----BEGIN PRIVATE KEY-----");
                                    EXPECT_STREQ(private_key.substr(private_key.length() - 26).c_str(),
                                                 "-----END PRIVATE KEY-----\n");

                                    EXPECT_STREQ(public_key.substr(0,26).c_str(), "-----BEGIN PUBLIC KEY-----");
                                    EXPECT_STREQ(public_key.substr(public_key.length() - 25).c_str(),
                                                 "-----END PUBLIC KEY-----\n");
                                }, [](const string::secure_string &error_message) {
                                    EXPECT_TRUE(false) << error_message;
                                });
}

TEST(Rsa, GenerateKeyPair) {
    try {
        auto controller = Rsa{};

        const auto &[fst, snd] = controller.generate_keypair();
        EXPECT_STREQ(fst.substr(0,27).c_str(), "-----BEGIN PRIVATE KEY-----");
        EXPECT_STREQ(fst.substr(fst.length() - 26).c_str(),
                     "-----END PRIVATE KEY-----\n");

        EXPECT_STREQ(snd.substr(0,26).c_str(), "-----BEGIN PUBLIC KEY-----");
        EXPECT_STREQ(snd.substr(snd.length() - 25).c_str(),
                     "-----END PUBLIC KEY-----\n");
    } catch (const std::exception &ex) {
        EXPECT_TRUE(false) << ex.what();
    }
}

TEST(Rsa, EncryptDecryptAsync) {
    auto controller = Rsa{};
    auto test_data = string::secure_string{"some data to encrypt"};

    controller.encrypt(test_public_key, test_data, [&controller, test_data](const string::secure_string &cipher_text) {
                           controller.decrypt(test_private_key, cipher_text,
                                              [&controller, test_data](const string::secure_string &clear_text) {
                                                  EXPECT_STREQ(clear_text.c_str(), test_data.c_str());
                                              }, [](const string::secure_string &error_message) {
                                                  EXPECT_TRUE(false) << error_message;
                                              }
                           );
                       }, [](const string::secure_string &error_message) {
                           EXPECT_TRUE(false) << error_message;
                       });
}

TEST(Rsa, EncryptDecrypt) {
    try {
        auto controller = Rsa{};
        const auto &test_data = string::secure_string{"some data to encrypt"};
        const auto &cipher_text = controller.encrypt(test_public_key, test_data);
        const auto &clear_text = controller.decrypt(test_private_key, cipher_text);
        EXPECT_STREQ(clear_text.c_str(), test_data.c_str());
    } catch (const std::exception &ex) {
        EXPECT_TRUE(false) << ex.what();
    }
}

TEST(Rsa, SignVerifyAsync) {
    auto controller = Rsa{};
    auto test_data = string::secure_string{"some data to encrypt"};

    controller.sign(test_private_key, test_data, [&controller, test_data](const string::secure_string &signature) {
                        controller.verify(test_public_key, test_data, signature,
                                          []() {
                                          }, [](const string::secure_string &error_message) {
                                              EXPECT_TRUE(false) << error_message;
                                          }
                        );
                    }, [](const string::secure_string &error_message) {
                        EXPECT_TRUE(false) << error_message;
                    });
}

TEST(Rsa, SignVerify) {
    try {
        auto controller = Rsa{};
        const auto &test_data = string::secure_string{"some data to encrypt"};
        const auto &signature = controller.sign(test_private_key, test_data);
        const auto is_verified = controller.verify(test_public_key, test_data, signature);
        EXPECT_TRUE(is_verified);
    } catch (const std::exception &ex) {
        EXPECT_TRUE(false) << ex.what();
    }
}

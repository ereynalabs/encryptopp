/**
* @copyright Copyright (C) 2024, Ereyna Labs Ltd. - All Rights Reserved
 * @file Base64Ctrl.spec.cc
 * @parblock
 * This file is subject to the terms and conditions defined in file 'LICENSE.md',
 * which is part of this source code package.  Proprietary and confidential.
 * @endparblock
 * @author Dave Linten <david@ereynalabs.com>
 */

#include <gtest/gtest.h>
#include <Base64Ctrl.h>
#include "secure_string.h"
#include <encryptopp.h>

/**
 * WARNING: Implementations of secure_string CANNOT be debugged.  I.e. It is a PROPER secure_string that actively
 *          prevents peeking, and therefore resolution of variables using it will crash the software and PID.
 */
using namespace encryptopp;

namespace {
    constexpr int data_size = 4096;
    string::secure_string random_fixed_text { "The time has come for all good men to come to the aid of their party. 1"};
}

TEST(Base64, EncodeDecodeAlphaAsync) {
    auto controller = Base64{};

    string::secure_string random_data;

    for (int idx = 0; idx < data_size; ++idx) {
        random_data.push_back(rand() % 26 + 'a');
    }

    controller.encode(random_data,
                      [random_data, &controller](
                  const string::secure_string &encoded_text) {
                          controller.decode(encoded_text,
                                            [random_data](const string::secure_string &plain_text) {
                                                EXPECT_STREQ(random_data.c_str(), plain_text.c_str());
                                            }, [](const string::secure_string &error_message) {
                                                //EXPECT_TRUE(true);
                                                EXPECT_TRUE(false) << error_message;
                                            });
                      }, [](const string::secure_string &error_message) {
                          //EXPECT_TRUE(true);
                          EXPECT_TRUE(false) << error_message;
                      }, false, false);
}

TEST(Base64, EncodeDecodeAlpha) {
    auto controller = Base64{};

    string::secure_string random_data;

    for (int idx = 0; idx < data_size; ++idx) {
        random_data.push_back(rand() % 26 + 'a');
    }

    const auto& encoded_text = controller.encode(random_data);
    const auto& decoded_text = controller.decode(encoded_text);
    EXPECT_STREQ(decoded_text.c_str(), random_data.c_str());
}

TEST(Base64, EncodeDecodeAlphaUrlAsync) {
    auto controller = Base64{};

    string::secure_string random_data;

    for (int idx = 0; idx < data_size; ++idx) {
        random_data.push_back(rand() % 26 + 'a');
    }

    controller.encode(random_data,
                      [random_data, &controller](
                  const string::secure_string &encoded_text) {
                          // CHECK(1 == 2);
                          // auto decrypt_controller = Aes {};
                          controller.decode(encoded_text,
                                            [random_data](const string::secure_string &plain_text) {
                                                EXPECT_STREQ(random_data.c_str(), plain_text.c_str());
                                            }, [](const string::secure_string &error_message) {
                                                //EXPECT_TRUE(true);
                                                EXPECT_TRUE(false) << error_message;
                                            });
                      }, [](const string::secure_string &error_message) {
                          //EXPECT_TRUE(true);
                          EXPECT_TRUE(false) << error_message;
                      }, false, false);
}

TEST(Base64, EncodeDecodeAlphaUrl) {
    auto controller = Base64{};

    string::secure_string random_data;

    for (int idx = 0; idx < data_size; ++idx) {
        random_data.push_back(rand() % 26 + 'a');
    }

    const auto& encoded_text = controller.encode(random_data, false, true);
    const auto& decoded_text = controller.decode(encoded_text);
    EXPECT_STREQ(decoded_text.c_str(), random_data.c_str());
}

TEST(Base64, EncodeDecodeAlphaPaddedAsync) {
    auto controller = Base64{};

    string::secure_string random_data;

    for (int idx = 0; idx < data_size; ++idx) {
        random_data.push_back(rand() % 26 + 'a');
    }

    controller.encode(random_data,
                      [random_data, &controller](
                  const string::secure_string &encoded_text) {
                          // CHECK(1 == 2);
                          // auto decrypt_controller = Aes {};
                          controller.decode(encoded_text,
                                            [random_data](const string::secure_string &plain_text) {
                                                EXPECT_STREQ(random_data.c_str(), plain_text.c_str());
                                            }, [](const string::secure_string &error_message) {
                                                //EXPECT_TRUE(true);
                                                EXPECT_TRUE(false) << error_message;
                                            });
                      }, [](const string::secure_string &error_message) {
                          //EXPECT_TRUE(true);
                          EXPECT_TRUE(false) << error_message;
                      }, true, false);
}

TEST(Base64, EncodeDecodeAlphaPadded) {
    auto controller = Base64{};

    string::secure_string random_data;

    for (int idx = 0; idx < data_size; ++idx) {
        random_data.push_back(rand() % 26 + 'a');
    }

    const auto& encoded_text = controller.encode(random_data, true, false);
    const auto& decoded_text = controller.decode(encoded_text);
    EXPECT_STREQ(decoded_text.c_str(), random_data.c_str());
}

TEST(Base64, EncodeDecodeAsciiAsync) {
    auto controller = Base64{};

    string::secure_string random_data;

    for (int idx = 0; idx < data_size; ++idx) {
        random_data.push_back(rand() % 93 + '(');
    }

    controller.encode(random_data,
                      [random_data, &controller](
                  const string::secure_string &encoded_text) {
                          // CHECK(1 == 2);
                          // auto decrypt_controller = Aes {};
                          controller.decode(encoded_text,
                                            [random_data](const string::secure_string &plain_text) {
                                                EXPECT_STREQ(random_data.c_str(), plain_text.c_str());
                                            }, [](const string::secure_string &error_message) {
                                                //EXPECT_TRUE(true);
                                                EXPECT_TRUE(false) << error_message;
                                            });
                      }, [](const string::secure_string &error_message) {
                          //EXPECT_TRUE(true);
                          EXPECT_TRUE(false) << error_message;
                      }, false, false);
}

TEST(Base64, EncodeDecodeAscii) {
    auto controller = Base64{};

    string::secure_string random_data;

    for (int idx = 0; idx < data_size; ++idx) {
        random_data.push_back(rand() % 93 + '(');
    }

    const auto& encoded_text = controller.encode(random_data);
    const auto& decoded_text = controller.decode(encoded_text);
    EXPECT_STREQ(decoded_text.c_str(), random_data.c_str());
}

TEST(Base64, EncodeDecodeAsciiUrlAsync) {
    auto controller = Base64{};

    string::secure_string random_data;

    for (int idx = 0; idx < data_size; ++idx) {
        random_data.push_back(rand() % 93 + '(');
    }

    controller.encode(random_data,
                      [random_data, &controller](
                  const string::secure_string &encoded_text) {
                          // CHECK(1 == 2);
                          // auto decrypt_controller = Aes {};
                          controller.decode(encoded_text,
                                            [random_data](const string::secure_string &plain_text) {
                                                EXPECT_STREQ(random_data.c_str(), plain_text.c_str());
                                            }, [](const string::secure_string &error_message) {
                                                //EXPECT_TRUE(true);
                                                EXPECT_TRUE(false) << error_message;
                                            });
                      }, [](const string::secure_string &error_message) {
                          //EXPECT_TRUE(true);
                          EXPECT_TRUE(false) << error_message;
                      }, false, false);
}

TEST(Base64, EncodeDecodeAsciiUrl) {
    auto controller = Base64{};

    string::secure_string random_data;

    for (int idx = 0; idx < data_size; ++idx) {
        random_data.push_back(rand() % 93 + '(');
    }

    const auto& encoded_text = controller.encode(random_data, false, true);
    const auto& decoded_text = controller.decode(encoded_text);
    EXPECT_STREQ(decoded_text.c_str(), random_data.c_str());
}

TEST(Base64, EncodeDecodeAsciiPaddedAsync) {
    auto controller = Base64{};

    string::secure_string random_data;

    for (int idx = 0; idx < data_size; ++idx) {
        random_data.push_back(rand() % 93 + '(');
    }

    controller.encode(random_data,
                      [random_data, &controller](
                  const string::secure_string &encoded_text) {
                          // CHECK(1 == 2);
                          // auto decrypt_controller = Aes {};
                          controller.decode(encoded_text,
                                            [random_data](const string::secure_string &plain_text) {
                                                EXPECT_STREQ(random_data.c_str(), plain_text.c_str());
                                            }, [](const string::secure_string &error_message) {
                                                //EXPECT_TRUE(true);
                                                EXPECT_TRUE(false) << error_message;
                                            });
                      }, [](const string::secure_string &error_message) {
                          //EXPECT_TRUE(true);
                          EXPECT_TRUE(false) << error_message;
                      }, true, false);
}

TEST(Base64, EncodeDecodeAsciiPadded) {
    auto controller = Base64{};

    string::secure_string random_data;

    for (int idx = 0; idx < data_size; ++idx) {
        random_data.push_back(rand() % 93 + '(');
    }

    const auto& encoded_text = controller.encode(random_data, true, false);
    const auto& decoded_text = controller.decode(encoded_text);
    EXPECT_STREQ(decoded_text.c_str(), random_data.c_str());
}

TEST(Base64, EncodeDecodeUtf8Async) {
    auto controller = Base64{};

    string::secure_string random_data = random_fixed_text;

    controller.encode(random_data,
                      [random_data, &controller](
                  const string::secure_string &encoded_text) {
                          controller.decode(encoded_text,
                                            [random_data](const string::secure_string &plain_text) {
                                                EXPECT_STREQ(random_data.c_str(), plain_text.c_str());
                                            }, [](const string::secure_string &error_message) {
                                                EXPECT_TRUE(false) << error_message;
                                            });
                      }, [](const string::secure_string &error_message) {
                          EXPECT_TRUE(false) << error_message;
                      }, false, false);
}

TEST(Base64, EncodeDecodeUtf8) {
    auto controller = Base64{};

    string::secure_string random_data;

    for (int idx = 0; idx < data_size; ++idx) {
        random_data.push_back(rand() % 26 + 'a');
    }

    const auto& encoded_text = controller.encode(random_data);
    const auto& decoded_text = controller.decode(encoded_text);
    EXPECT_STREQ(decoded_text.c_str(), random_data.c_str());
}

TEST(Base64, EncodeDecodeUtf8UrlAsync) {
    auto controller = Base64{};

    string::secure_string random_data;

    for (int idx = 0; idx < data_size; ++idx) {
        random_data.push_back(rand() % 127 + '(');
    }

    controller.encode(random_data,
                      [random_data, &controller](
                  const string::secure_string &encoded_text) {
                          controller.decode(encoded_text,
                                            [random_data](const string::secure_string &plain_text) {
                                                EXPECT_STREQ(random_data.c_str(), plain_text.c_str());
                                            }, [](const string::secure_string &error_message) {
                                                //EXPECT_TRUE(true);
                                                EXPECT_TRUE(false) << error_message;
                                            });
                      }, [](const string::secure_string &error_message) {
                          //EXPECT_TRUE(true);
                          EXPECT_TRUE(false) << error_message;
                      }, false, true);
}

TEST(Base64, EncodeDecodeUtf8Url) {
    auto controller = Base64{};

    string::secure_string random_data;

    for (int idx = 0; idx < data_size; ++idx) {
        random_data.push_back(rand() % 127 + '(');
    }

    const auto& encoded_text = controller.encode(random_data, false, true);
    const auto& decoded_text = controller.decode(encoded_text);
    EXPECT_STREQ(decoded_text.c_str(), random_data.c_str());
}

TEST(Base64, EncodeDecodeUtf8PaddedAsync) {
    auto controller = Base64{};

    string::secure_string random_data;

    for (int idx = 0; idx < data_size; ++idx) {
        random_data.push_back(rand() % 127 + '(');
    }

    controller.encode(random_data,
                      [random_data, &controller](
                  const string::secure_string &encoded_text) {
                          controller.decode(encoded_text,
                                            [random_data](const string::secure_string &plain_text) {
                                                EXPECT_STREQ(random_data.c_str(), plain_text.c_str());
                                            }, [](const string::secure_string &error_message) {
                                                EXPECT_TRUE(false) << error_message;
                                            });
                      }, [](const string::secure_string &error_message) {
                          EXPECT_TRUE(false) << error_message;
                      }, true, false);
}

TEST(Base64, EncodeDecodeUtf8Padded) {
    auto controller = Base64{};

    string::secure_string random_data;

    for (int idx = 0; idx < data_size; ++idx) {
        random_data.push_back(rand() % 127 + '(');
    }

    const auto& encoded_text = controller.encode(random_data, true, false);
    const auto& decoded_text = controller.decode(encoded_text);
    EXPECT_STREQ(decoded_text.c_str(), random_data.c_str());
}
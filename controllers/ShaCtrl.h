/**
* @copyright Copyright (C) 2025, Ereyna Labs Ltd. - All Rights Reserved
 * @file ShaCtrl.h
 * @parblock
 * This file is subject to the terms and conditions defined in file 'LICENSE.md',
 * which is part of this source code package.  Proprietary and confidential.
 * @endparblock
 * @author Dave Linten <david@ereynalabs.com>
 */

#pragma once

#include "secure_string.h"

#include <argparse/argparse.hpp>
#include "ShaCtrlBase.h"

namespace encryptopp {
    class Sha final : ShaBase, public argparse::Args {
    public:
        enum sha_algo {
            sha1,
            sha256,
            sha512
        };

        void sha1_hash(const string::secure_string &clear_text,
                       std::function<void(const string::secure_string &cipher_text)> &&success_callback,
                       std::function<void(const string::secure_string &error_message)> &&failure_callback) override;

        string::secure_string sha1_hash(const string::secure_string &clear_text);

        void sha256_hash(const string::secure_string &clear_text,
                         std::function<void(const string::secure_string &cipher_text)> &&success_callback,
                         std::function<void(const string::secure_string &error_message)> &&failure_callback) override;

        string::secure_string sha256_hash(const string::secure_string &clear_text);

        void sha512_hash(const string::secure_string &clear_text,
                         std::function<void(const string::secure_string &cipher_text)> &&success_callback,
                         std::function<void(const string::secure_string &error_message)> &&failure_callback) override;

        string::secure_string sha512_hash(const string::secure_string &clear_text);

    private:
        sha_algo &algo_ = kwarg("a,algo", "An Algorithm to use [enum] input");
        std::string &input_ = arg("Use the given <input> to create a hash with.");

        int run() override;
    };

}

/**
 * @copyright Copyright (C) 2024, Ereyna Labs Ltd. - All Rights Reserved
 * @file Base64Ctrl.h
 * @parblock
 * This file is subject to the terms and conditions defined in file 'LICENSE.md',
 * which is part of this source code package.  Proprietary and confidential.
 * @endparblock
 * @author Dave Linten <david@ereynalabs.com>
 */

#pragma once

#include "secure_string.h"

#include "Base64CtrlBase.h"
#include <argparse/argparse.hpp>

namespace encryptopp {
    class Base64 final : public Base64Base, public argparse::Args {
    public:
        void encode(const string::secure_string &clear_text,
                    std::function<void(const string::secure_string &encoded_text)> &&success_callback,
                    std::function<void(const string::secure_string &error_message)> &&failure_callback,
                    bool padded, bool url) override;

        string::secure_string encode(const string::secure_string &clear_text, bool padded = false, bool url = false);

        void decode(const string::secure_string &encoded_text,
                    std::function<void(const string::secure_string &clear_text)> &&success_callback,
                    std::function<void(const string::secure_string &error_message)> &&failure_callback) override;

        string::secure_string decode(const string::secure_string &encoded_text);


    private:
        int run() override;

        bool &encode_ = flag("e,encode", "Encode a string").set_default(true);
        bool &decode_ = flag("d,decode", "Decode a string").set_default(false);
        bool &padded_ = flag("p,padded", "Output base64 as padded").set_default(false);
        bool &url_ = flag("u,url", "Output base64 as URL encoded").set_default(false);
        std::string &input_ = arg("Input to encode or decode");
    };
}

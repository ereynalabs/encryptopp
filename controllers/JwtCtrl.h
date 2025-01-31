/**
 * @copyright Copyright (C) 2024, Ereyna Labs Ltd. - All Rights Reserved
 * @file JwtCtrl.h
 * @parblock
 * This file is subject to the terms and conditions defined in file 'LICENSE.md',
 * which is part of this source code package.  Proprietary and confidential.
 * @endparblock
 * @author Dave Linten <david@ereynalabs.com>
 */

#pragma once

#include "secure_string.h"

#include "JwtCtrlBase.h"
#include <argparse/argparse.hpp>

namespace encryptopp {
    class Jwt final : JwtBase, public argparse::Args {
    public:
        void encode(const models::JwtPayload &payload, const string::secure_string &secret,
                    std::function<void(const string::secure_string &token)> &&success_callback,
                    std::function<void(const string::secure_string &error_message)> &&failure_callback) override;

        string::secure_string encode(const models::JwtPayload &payload, const string::secure_string &secret);

        void decode(const string::secure_string &token, const string::secure_string &secret,
                    std::function<void(const models::JwtPayload &payload)> &&success_callback,
                    std::function<void(const string::secure_string &error_message)> &&failure_callback) override;

       models::JwtPayload decode(const string::secure_string &token, const string::secure_string &secret);

    private:
        int run() override;

        bool &encode_ = flag("e,encode", "Encode a JWT").set_default(true);
        bool &decode_ = flag("d,decode", "Decode a JWT").set_default(false);
        std::string &secret_ = kwarg("s,secret", "JWT HMAC Secret").set_default("");
        std::string &input_ = arg("Input to encode or decode");
    };
}

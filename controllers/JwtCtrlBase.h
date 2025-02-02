/**
* @copyright Copyright (C) 2024, Ereyna Labs Ltd. - All Rights Reserved
 * @file JwtCtrlBase.h
 * @parblock
 * This file is subject to the terms and conditions defined in file 'LICENSE.md',
 * which is part of this source code package.  Proprietary and confidential.
 * @endparblock
 * @author Dave Linten <david@ereynalabs.com>
 */

#pragma once

#include <AesCtrlBase.h>
#include <Base64CtrlBase.h>
#include <functional>
#include "secure_string.h"
#include <string>
#include <json/json.h>
#include <JwtPayload.h>

namespace encryptopp {
    class JwtBase : private AesBase {
    public:
        virtual void encode(const models::JwtPayload &payload, const string::secure_string& secret,
                               std::function<void(const string::secure_string& token)>&& success_callback,
                               std::function<void(const string::secure_string& error_message)>&& failure_callback);

        virtual void decode(const string::secure_string& token, const string::secure_string& secret,
                                 std::function<void(const models::JwtPayload &payload)>&& success_callback,
                                 std::function<void(const string::secure_string& error_message)>&& failure_callback);


    protected:
        /// Ensure that subclasses inherited from this class are instantiated.
        JwtBase() = default;
        ~JwtBase() override = default;
    };
}

/**
* @copyright Copyright (C) 2024, Ereyna Labs Ltd. - All Rights Reserved
 * @file Base64CtrlBase.h
 * @parblock
 * This file is subject to the terms and conditions defined in file 'LICENSE.md',
 * which is part of this source code package.  Proprietary and confidential.
 * @endparblock
 * @author Dave Linten <david@ereynalabs.com>
 */

#pragma once

#include <functional>
#include "secure_string.h"
#include <string>

namespace encryptopp {
    class Base64Base {
    public:
        virtual void encode(const string::secure_string& clear_text,
                            std::function<void(const string::secure_string& encoded_text)>&& success_callback,
                            std::function<void(const string::secure_string& error_message)>&& failure_callback,
                            bool padded, bool url_safe);

        virtual void decode(const string::secure_string& encoded_text,
                            std::function<void(const string::secure_string& clear_text)>&& success_callback,
                            std::function<void(const string::secure_string& error_message)>&& failure_callback);

    protected:
        /// Ensure that subclasses inherited from this class are instantiated.
        Base64Base() = default;
        virtual ~Base64Base() = default;
    };
}

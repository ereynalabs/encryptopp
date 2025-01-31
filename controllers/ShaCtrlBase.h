/**
* @copyright Copyright (C) 2024, Ereyna Labs Ltd. - All Rights Reserved
 * @file ShaCtrlBase.h
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
    class ShaBase {
    public:
        virtual void sha1_hash(const string::secure_string& clear_text,
                               std::function<void(const string::secure_string& cipher_text)>&& success_callback,
                               std::function<void(const string::secure_string& error_message)>&& failure_callback);

        virtual void sha256_hash(const string::secure_string& clear_text,
                                 std::function<void(const string::secure_string& cipher_text)>&& success_callback,
                                 std::function<void(const string::secure_string& error_message)>&& failure_callback);

        virtual void sha512_hash(const string::secure_string& clear_text,
                                 std::function<void(const string::secure_string& cipher_text)>&& success_callback,
                                 std::function<void(const string::secure_string& error_message)>&& failure_callback);


    protected:
        /// Ensure that subclasses inherited from this class are instantiated.
        ShaBase();

        virtual ~ShaBase() = default;
    };
}

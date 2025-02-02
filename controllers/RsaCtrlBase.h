/**
* @copyright Copyright (C) 2024, Ereyna Labs Ltd. - All Rights Reserved
 * @file RsaCtrlBase.h
 * @parblock
 * This file is subject to the terms and conditions defined in file 'LICENSE.md',
 * which is part of this source code package.  Proprietary and confidential.
 * @endparblock
 * @author Dave Linten <david@ereynalabs.com>
 */

#pragma once

#include <Base64CtrlBase.h>
#include <functional>
#include "secure_string.h"
#include <string>

namespace encryptopp {
    class RsaBase : private Base64Base {
    public:
        virtual void encrypt(const string::secure_string& public_key,
                             const string::secure_string& clear_text,
                             std::function<void(const string::secure_string& cipher_text)>&& success_callback,
                             std::function<void(const string::secure_string& error_message)>&& failure_callback);

        virtual void sign(const string::secure_string& private_key,
                          const string::secure_string& clear_text,
                          std::function<void(const string::secure_string& signature_text)>&& success_callback,
                          std::function<void(const string::secure_string& error_message)>&& failure_callback);

        virtual void verify(const string::secure_string& public_key,
                            const string::secure_string& clear_text,
                            const string::secure_string& signature,
                            std::function<void()>&& success_callback,
                            std::function<void(const string::secure_string& error_message)>&& failure_callback);

        virtual void decrypt(const string::secure_string& private_key,
                             const string::secure_string& cipher_text,
                             std::function<void(const string::secure_string& clear_text)>&& success_callback,
                             std::function<void(const string::secure_string& error_message)>&& failure_callback);

        virtual void generate_keypair(std::function<void(const string::secure_string& private_key,
                                                 const string::secure_string& public_key)>&& success_callback,
                              std::function<void(
                                  const string::secure_string& error_message)>&& failure_callback);
    protected:
        /// Ensure that subclasses inherited from this class are instantiated.
        RsaBase() = default;
        ~RsaBase() override = default;
    };
}

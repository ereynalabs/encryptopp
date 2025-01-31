/**
 * @copyright Copyright (C) 2024, Ereyna Labs Ltd. - All Rights Reserved
 * @file AesCtrl.h
 * @parblock
 * This file is subject to the terms and conditions defined in file 'LICENSE.md',
 * which is part of this source code package.  Proprietary and confidential.
 * @endparblock
 * @author Dave Linten <david@ereynalabs.com>
 */

#pragma once

#include "secure_string.h"

#include "AesCtrlBase.h"
#include <argparse/argparse.hpp>


namespace encryptopp {
    class Aes final : AesBase, public argparse::Args {
    public:
        void encrypt(const string::secure_string &key,
                     const string::secure_string &iv,
                     const string::secure_string &clear_text,
                     std::function<void(const string::secure_string &cipher_text)> &&success_callback,
                     std::function<void(const string::secure_string &error_message)> &&failure_callback) override;

        string::secure_string encrypt(const string::secure_string &key,
                                      const string::secure_string &iv,
                                      const string::secure_string &clear_text);

        void decrypt(const string::secure_string &key,
                     const string::secure_string &iv,
                     const string::secure_string &cipher_text,
                     std::function<void(const string::secure_string &clear_text)> &&success_callback,
                     std::function<void(const string::secure_string &error_message)> &&failure_callback) override;


        string::secure_string decrypt(const string::secure_string &key,
                                       const string::secure_string &iv,
                                       const string::secure_string &cipher_text);

        void sign(const string::secure_string &key,
                  const string::secure_string &clear_text,
                  std::function<void(const string::secure_string &signature)> &&success_callback,
                  std::function<void(const string::secure_string &error_message)> &&failure_callback) override;

        string::secure_string sign(const string::secure_string &key,
                                   const string::secure_string &clear_text);

        void verify(const string::secure_string &key,
                    const string::secure_string &clear_text,
                    const string::secure_string &signature,
                    std::function<void()> &&success_callback,
                    std::function<void(const string::secure_string &error_message)> &&failure_callback) override;

        bool verify(const string::secure_string &key,
                    const string::secure_string &clear_text,
                    const string::secure_string &signature);

    private:
        int run() override;

        std::string &encrypt_secret_ = kwarg("e,encrypt", "Encrypt using an AES Secret").set_default("");
        std::string &decrypt_secret_ = kwarg("d,decrypt", "Decrypt using an AES Secret").set_default("");
        std::string &init_vector_ = kwarg("i,initvector", "AES Initialisation vector").set_default("");
        std::string &signature_secret_ = kwarg("s,sign", "Sign using an AES Secret").set_default("");
        std::string &signature_ = kwarg("x,signature", "The AES HMAC SHA256 Signature").set_default("");
        std::string &verify_secret_ = kwarg("v,verify", "Verify using an AES Secret and signature").set_default("");
        std::string &input_ = arg("Input to encrypt or decrypt").set_default("");
    };
}

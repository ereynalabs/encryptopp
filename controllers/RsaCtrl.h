/**
* @copyright Copyright (C) 2025, Ereyna Labs Ltd. - All Rights Reserved
 * @file RsaCtrl.h
 * @parblock
 * This file is subject to the terms and conditions defined in file 'LICENSE.md',
 * which is part of this source code package.  Proprietary and confidential.
 * @endparblock
 * @author Dave Linten <david@ereynalabs.com>
 */

#pragma once

#include "secure_string.h"

#include "RsaCtrlBase.h"
#include <argparse/argparse.hpp>

namespace encryptopp {
    class Rsa final : RsaBase, public argparse::Args {
    public:
        void encrypt(const string::secure_string &public_key,
                     const string::secure_string &clear_text,
                     std::function<void(const string::secure_string &cipher_text)> &&success_callback,
                     std::function<void(const string::secure_string &error_message)> &&failure_callback) override;

        string::secure_string encrypt(const string::secure_string &public_key,
                                      const string::secure_string &clear_text);

        void sign(const string::secure_string &private_key,
                  const string::secure_string &clear_text,
                  std::function<void(const string::secure_string &signature_text)> &&success_callback,
                  std::function<void(const string::secure_string &error_message)> &&failure_callback) override;

        string::secure_string sign(const string::secure_string &private_key,
                                   const string::secure_string &clear_text);

        void verify(const string::secure_string &public_key,
                    const string::secure_string &clear_text,
                    const string::secure_string &signature,
                    std::function<void()> &&success_callback,
                    std::function<void(const string::secure_string &error_message)> &&failure_callback) override;

        bool verify(const string::secure_string &public_key,
                                     const string::secure_string &clear_text,
                                     const string::secure_string &signature);

        void decrypt(const string::secure_string &private_key,
                     const string::secure_string &cipher_text,
                     std::function<void(const string::secure_string &clear_text)> &&success_callback,
                     std::function<void(const string::secure_string &error_message)> &&failure_callback) override;

        string::secure_string decrypt(const string::secure_string &private_key,
                                      const string::secure_string &cipher_text);

        void generate_keypair(std::function<void(const string::secure_string &private_key,
                                                 const string::secure_string &public_key)> &&success_callback,
                              std::function<void(
                                  const string::secure_string &error_message)> &&failure_callback) override;

        std::pair<string::secure_string, string::secure_string> generate_keypair();

    private:
        string::secure_string &public_key_path_ = kwarg("e,encrypt", "Encrypt using a public key file").set_default("");
        std::string &private_key_path_ = kwarg("d,decrypt", "Decrypt using a private key file").set_default("");
        std::string &sign_private_key_ = kwarg("s,sign", "Sign using a private key").set_default("");
        std::string &signature_ = kwarg("x,signature", "The RSA Signature").set_default("");
        std::string &verify_public_key_path_ = kwarg("v,verify", "Verify using a public key and signature").
                set_default("");
        std::string &input_ = arg("Input to encrypt or decrypt").set_default("");
        bool &generate_ = flag("g,generate",
                               "Generates an RSA Key pair, uses -e and -d to denote "
                               "files to write, othersie will output as a string");

        int run() override;
    };
}

namespace encryptopp {
    // void rsa_encrypt(const std::string &public_key,
    //                  const std::string &clear_text,
    //                  std::function<void(const std::string &cipher_text)> &&success_callback,
    //                  std::function<void(const std::string &error_message)> &&failure_callback);
    //
    // void rsa_decrypt(const std::string &private_key,
    //                  const std::string &cipher_text,
    //                  std::function<void(const std::string &clear_text)> &&success_callback,
    //                  std::function<void(const std::string &error_message)> &&failure_callback);
    //
    // void rsa_sign(const std::string &private_key,
    //               const std::string &clear_text,
    //               std::function<void(const std::string &signature_text)> &&success_callback,
    //               std::function<void(const std::string &error_message)> &&failure_callback);
    //
    // void rsa_verify(const std::string &public_key,
    //                 const std::string &clear_text,
    //                 const std::string &signature,
    //                 std::function<void()> &&success_callback,
    //                 std::function<void(const std::string &error_message)> &&failure_callback);
    //
    // void rsa_generate_keypair(std::function<void(const std::string &private_key,
    //                                              const std::string &public_key)> &&success_callback,
    //                           std::function<void(
    //                               const std::string &error_message)> &&failure_callback);
    //
    // struct rsa_args final : argparse::Args {
    //     std::string &encrypt = kwarg("e,encrypt", "Encrypt using a public key file").set_default("");
    //     std::string &decrypt = kwarg("d,decrypt", "Decrypt using a private key file").set_default("");
    //     std::string &sign = kwarg("s,sign", "Sign using a private key").set_default("");
    //     std::string &signature = kwarg("x,signature", "The RSA Signature").set_default("");
    //     std::string &verify = kwarg("v,verify", "Verify using a public key and signature").set_default("");
    //     std::string &input = arg("Input to encrypt or decrypt").set_default("");
    //     bool &generate = flag("g,generate",
    //                           "Generates an RSA Key pair, uses -e and -d to denote "
    //                           "files to write, othersie will output as a string");
    //
    //
    //     int run() override;
    // };
}

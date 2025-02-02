/**
* @copyright Copyright (C) 2025, Ereyna Labs Ltd. - All Rights Reserved
 * @file Base64CtrlBase.cc
 * @parblock
 * This file is subject to the terms and conditions defined in file 'LICENSE.md',
 * which is part of this source code package.  Proprietary and confidential.
 * @endparblock
 * @author Dave Linten <david@ereynalabs.com>
 */

#include "Base64CtrlBase.h"

#include <string>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

namespace encryptopp {

    void Base64Base::encode(const encryptopp::string::secure_string& clear_text,
                                    std::function<void(const encryptopp::string::secure_string& encoded_text)>&& success_callback,
                                std::function<void(const encryptopp::string::secure_string& error_message)>&& failure_callback,
                                const bool padded, const bool url_safe) {
        try {
            BIO* b64 = nullptr;
            BIO* bio = BIO_new(BIO_s_mem());
            b64 = BIO_new(BIO_f_base64());

            BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

            bio = BIO_push(b64, bio);
            BIO_write(bio, clear_text.c_str(), clear_text.length());
            BIO_flush(bio);
            BUF_MEM* buffer_ptr;
            BIO_get_mem_ptr(bio, &buffer_ptr);
            encryptopp::string::secure_string encoded(buffer_ptr->data, buffer_ptr->length);
            BIO_free_all(bio);

            if(!padded) {
                 // Remove any padding characters
                size_t padding = encoded.find('=');
                if (padding != encryptopp::string::secure_string::npos)
                    encoded.erase(padding);
            }

            if(url_safe) {
                // Replace '+' with '-' and '/' with '_'
                for (char &ch : encoded) {
                    if (ch == '+') ch = '-';
                    else if (ch == '/') ch = '_';
                }
            }

            (success_callback)(encoded);
        } catch (std::exception &ex) {
            (failure_callback)(ex.what());
        }
    }

    void Base64Base::decode(const encryptopp::string::secure_string& encoded_text,
                                std::function<void(const encryptopp::string::secure_string& clear_text)>&& success_callback,
                                std::function<void(const encryptopp::string::secure_string& error_message)>&& failure_callback) {
        try {
            // Restore padding characters
            encryptopp::string::secure_string padded_text = encoded_text;
            padded_text.append((4 - padded_text.size() % 4) % 4, '=');

            // Replace '-' with '+' and '_' with '/'
            for (char &ch : padded_text) {
                if (ch == '-') ch = '+';
                else if (ch == '_') ch = '/';
            }

            BIO* bio = BIO_new_mem_buf(padded_text.c_str(), -1);
            BIO* b64 = BIO_new(BIO_f_base64());
            BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
            bio = BIO_push(b64, bio);
            char buffer[1024];
            encryptopp::string::secure_string decoded;
            int length;
            while ((length = BIO_read(bio, buffer, 1024)) > 0) {
                decoded.append(buffer, length);
            }
            BIO_free_all(bio);
            (success_callback)(decoded);
        }catch(std::exception &ex) {
            (failure_callback)(ex.what());
        }
    }
}

/**
* @copyright Copyright (C) 2025, Ereyna Labs Ltd. - All Rights Reserved
 * @file RsaCtrl.cc
 * @parblock
 * This file is subject to the terms and conditions defined in file 'LICENSE.md',
 * which is part of this source code package.  Proprietary and confidential.
 * @endparblock
 * @author Dave Linten <david@ereynalabs.com>
 */

#include "RsaCtrl.h"

#include <fstream>
#include <iostream>
#include <ShaCtrl.h>
#include <string>
#include <future>

namespace encryptopp {
    void Rsa::encrypt(const string::secure_string& public_key,
                          const string::secure_string& clear_text,
                          std::function<void(const string::secure_string& cipher_text)>&& success_callback,
                          std::function<void(const string::secure_string& error_message)>&& failure_callback) {
        RsaBase::encrypt(public_key, clear_text, std::move(success_callback), std::move(failure_callback));
    }

    string::secure_string Rsa::encrypt(const string::secure_string &public_key,
                              const string::secure_string &clear_text) {
        std::promise<int> promise;
        string::secure_string result;
        string::secure_string error_string;
        auto future = promise.get_future();

        encrypt(public_key, clear_text, [&promise, &result](const string::secure_string &cipher_text) {
                             result = string::secure_string{cipher_text};
                             promise.set_value(0);
                         }, [&promise, &error_string](const string::secure_string &error_message) {
                             error_string = error_message;
                             promise.set_value(1);
                         });

        if (future.get()) {
            throw std::runtime_error(std::string{error_string});
        }

        return std::move(result);
    }

    void Rsa::sign(const string::secure_string& private_key,
                       const string::secure_string& clear_text,
                       std::function<void(const string::secure_string& cipher_text)>&& success_callback,
                       std::function<void(const string::secure_string& error_message)>&& failure_callback) {
        RsaBase::sign(private_key, clear_text, std::move(success_callback), std::move(failure_callback));
    }

    string::secure_string Rsa::sign(const string::secure_string &private_key,
                           const string::secure_string &clear_text) {
        std::promise<int> promise;
        string::secure_string result;
        string::secure_string error_string;
        auto future = promise.get_future();

        sign(private_key, clear_text, [&promise, &result](const string::secure_string &signature) {
                             result = string::secure_string{signature};
                             promise.set_value(0);
                         }, [&promise, &error_string](const string::secure_string &error_message) {
                             error_string = error_message;
                             promise.set_value(1);
                         });

        if (future.get()) {
            throw std::runtime_error(std::string{error_string});
        }

        return std::move(result);
    }

    void Rsa::verify(const string::secure_string& public_key,
                         const string::secure_string& clear_text,
                         const string::secure_string& signature,
                         std::function<void()>&& success_callback,
                         std::function<void(const string::secure_string& error_message)>&& failure_callback) {
        RsaBase::verify(public_key, clear_text, signature, std::move(success_callback),
                            std::move(failure_callback));
    }

    bool Rsa::verify(const string::secure_string &public_key,
                             const string::secure_string &clear_text,
                             const string::secure_string &signature) {
        std::promise<int> promise;
        bool result;
        string::secure_string error_string;
        auto future = promise.get_future();

        verify(public_key, clear_text, signature, [&promise, &result]() {
                             result = true;
                             promise.set_value(0);
                         }, [&promise, &error_string](const string::secure_string &error_message) {
                             error_string = error_message;
                             promise.set_value(1);
                         });

        if (future.get()) {
            throw std::runtime_error(std::string{error_string});
        }

        return result;
    }

    void Rsa::decrypt(const string::secure_string& private_key,
                          const string::secure_string& cipher_text,
                          std::function<void(const string::secure_string& clear_text)>&& success_callback,
                          std::function<void(const string::secure_string& error_message)>&& failure_callback) {
        RsaBase::decrypt(private_key, cipher_text, std::move(success_callback), std::move(failure_callback));
    }

    string::secure_string Rsa::decrypt(const string::secure_string &private_key,
                              const string::secure_string &cipher_text) {
        std::promise<int> promise;
        string::secure_string result;
        string::secure_string error_string;
        auto future = promise.get_future();

        decrypt(private_key, cipher_text, [&promise, &result](const string::secure_string &clear_text) {
                             result = string::secure_string{clear_text};
                             promise.set_value(0);
                         }, [&promise, &error_string](const string::secure_string &error_message) {
                             error_string = error_message;
                             promise.set_value(1);
                         });

        if (future.get()) {
            throw std::runtime_error(std::string{error_string});
        }

        return std::move(result);
    }

    void Rsa::generate_keypair(std::function<void(const string::secure_string& private_key,
                                                      const string::secure_string& public_key)>&& success_callback,
                                   std::function<void(
                                       const string::secure_string& error_message)>&& failure_callback) {
        RsaBase::generate_keypair(std::move(success_callback), std::move(failure_callback));
    }

    std::pair<string::secure_string, string::secure_string> Rsa::generate_keypair() {
        std::promise<int> promise;
        std::pair<string::secure_string, string::secure_string> ppk_pair;
        string::secure_string error_string;
        auto future = promise.get_future();

        generate_keypair([&promise, &ppk_pair](const string::secure_string& private_key,
                                                      const string::secure_string& public_key) {
                             ppk_pair.first = private_key;
                             ppk_pair.second = public_key;
                             promise.set_value(0);
                         }, [&promise, &error_string](const string::secure_string &error_message) {
                             error_string = error_message;
                             promise.set_value(1);
                         });

        if (future.get()) {
            throw std::runtime_error(std::string{error_string});
        }

        return std::move(ppk_pair);
    }

    int Rsa::run() {
        try {
            if (generate_) {
                const auto& ppk_pair = generate_keypair();

                if (!private_key_path_.empty()) {
                    if (std::fstream private_key_fs{private_key_path_, std::fstream::out};
                        private_key_fs.is_open()) {
                        private_key_fs << ppk_pair.first;
                        private_key_fs.flush();
                        private_key_fs.close();
                        }
                    else {
                        std::cerr << "Could not open private key file " << private_key_path_ << " for writing." << std::endl;
                        return 1;
                    }
                }
                else {
                    std::cout << ppk_pair.first << std::endl;
                }

                if (!public_key_path_.empty()) {
                    if (std::fstream public_key_fs{public_key_path_.c_str(), std::fstream::out}; public_key_fs
                        .is_open()) {
                        public_key_fs << ppk_pair.second;
                        public_key_fs.flush();
                        public_key_fs.close();
                        }
                    else {
                        std::cerr << "Could not open public key file "
                                << public_key_path_ << " for writing." << std::endl;
                        return 1;
                    }
                }
                else {
                    std::cout << ppk_pair.second << std::endl;
                }

                return 0;
            }
        }
        catch (std::exception &ex) {
            std::cerr <<ex.what() << std::endl;
        }

        if (!public_key_path_.empty() && !input_.empty()) {
            if (std::ifstream public_key_fs{public_key_path_.c_str()};
                public_key_fs.is_open()) {
                string::secure_string public_key((std::istreambuf_iterator(public_key_fs)),
                                       (std::istreambuf_iterator<char>()));
                public_key_fs.close();

                const auto& cipher_text = encrypt(public_key, string::secure_string { input_ });
                std::cout << cipher_text;
            } else {
                std::cerr << "Unable to encrypt with given inputs." << std::endl;
                return 1;
            }

            return 0;
        }


        if (!private_key_path_.empty() && !input_.empty()) {
            if (std::ifstream public_key_fs{private_key_path_};
                public_key_fs.is_open()) {
                string::secure_string private_key((std::istreambuf_iterator(public_key_fs)),
                                       (std::istreambuf_iterator<char>()));
                public_key_fs.close();

                const auto& clear_text = decrypt(private_key, string::secure_string { input_ });
                std::cout << clear_text;
                } else {
                    std::cerr << "Unable to encrypt with given inputs." << std::endl;
                    return 1;
                }

            return 0;
        }

        if (!sign_private_key_.empty() && !input_.empty()) {
            if (std::ifstream private_key_fs{sign_private_key_};
                private_key_fs.is_open()) {
                string::secure_string private_key((std::istreambuf_iterator(private_key_fs)),
                                        (std::istreambuf_iterator<char>()));
                private_key_fs.close();

                const auto& signature = sign(private_key, string::secure_string { input_ });
                std::cout << signature;
            } else {
                std::cerr << "Unable to sign the content with given inputs." << std::endl;
                return 1;
            }

            return 0;
        }

        if (!verify_public_key_path_.empty() && !input_.empty()) {
            if (std::ifstream public_key_fs{verify_public_key_path_};
                public_key_fs.is_open()) {
                string::secure_string private_key((std::istreambuf_iterator(public_key_fs)),
                                        (std::istreambuf_iterator<char>()));
                public_key_fs.close();

                const auto& signature = sign(private_key, string::secure_string { input_ });
                std::cout << signature;
                } else {
                    std::cerr << "Unable to sign the content with given inputs." << std::endl;
                    return 1;
                }

            return 0;
        }

        std::cerr << "Unknown argument combination" << std::endl;
        return 1;
    }
}

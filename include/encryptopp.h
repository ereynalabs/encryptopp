/**
 * @copyright Copyright (C) 2024, Ereyna Labs Ltd. - All Rights Reserved
 * @file encryptopp.h
 * @parblock
 * This file is subject to the terms and conditions defined in file 'LICENSE.md',
 * which is part of this source code package.  Proprietary and confidential.
 * @endparblock
 * @author Dave Linten <david@ereynalabs.com>
 */

#pragma once

#include <string>
#include <AesCtrl.h>
#include <Base64Ctrl.h>
#include <JwtCtrl.h>
#include <RsaCtrl.h>
#include <ShaCtrl.h>

#include <argparse/argparse.hpp>

namespace encryptopp {
    struct application_args final : argparse::Args {
        bool& version = flag("v,version", "Print version");
        Aes& aes = subcommand("aes");
        Jwt& jwt = subcommand("jwt");
        Rsa& rsa = subcommand("rsa");
        Sha& sha = subcommand("sha");
        Base64& base64 = subcommand("base64");
    };
}

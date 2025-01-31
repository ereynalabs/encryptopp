/**
 * @copyright Copyright (C) 2024, Ereyna Labs Ltd. - All Rights Reserved
 * @file main.cc
 * @parblock
 * This file is subject to the terms and conditions defined in file 'LICENSE.md',
 * which is part of this source code package.  Proprietary and confidential.
 * @endparblock
 * @author Dave Linten <david@ereynalabs.com>
 */

#include <encryptopp.h>
#include <iostream>

int main(const int argc, char* argv[]) {
    auto args = argparse::parse<encryptopp::application_args>(argc, argv);

    if (args.version) {
        std::cout << "EnCryptoPP version 1.0.0" << std::endl;
        return 0;
    }

    return args.run_subcommands();
}

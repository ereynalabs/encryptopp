##
# @copyright Copyright (C) 2024, Ereyna Labs Ltd. - All Rights Reserved
# @file CMakeLists.txt
# @parblock
# This file is subject to the terms and conditions defined in file 'LICENSE.md',
# which is part of this source code package.  Proprietary and confidential.
# @endparblock
# @author Dave Linten <david@ereynalabs.com>
#


include(CheckIncludeFileCXX)

#FetchContent_Declare(
#        Catch2
#        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
#        GIT_TAG        v3.5.3
#)
#FetchContent_MakeAvailable(Catch2)

#FetchContent_Declare(
#        googletest
#        GIT_REPOSITORY  https://github.com/google/googletest.git
#        GIT_TAG         v1.14.0
#)

FetchContent_Declare(
        googletest
        SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../libraries/googletest"
)


# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

set (TEST_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/../controllers/AesCtrl.spec.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/../controllers/Base64Ctrl.spec.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/../controllers/JwtCtrl.spec.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/../controllers/RsaCtrl.spec.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/../controllers/ShaCtrl.spec.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/../main-lib.spec.cc
)

# Tests need to be added as executables first
add_executable(${APP_TEST_TARGET}
        ${TEST_SRC}
)

target_include_directories(${APP_TEST_TARGET} PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/tests
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/helpers)

find_package(OpenSSL)

if (OpenSSL_FOUND)

    message("*** Found OpenSSL, continuing to add tests")

    # I'm using C++17 in the test
    target_compile_features(${APP_TEST_TARGET} PRIVATE cxx_std_20)

    # Should be linked to the main library, as well as the Catch2 testing library
    target_link_libraries(${APP_TEST_TARGET} PRIVATE OpenSSL::Crypto ${APP_LIB_TARGET} GTest::gtest_main)

    include(GoogleTest)

    gtest_discover_tests(${APP_TEST_TARGET})

endif (OpenSSL_FOUND)


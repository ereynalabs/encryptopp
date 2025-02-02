##
# @copyright Copyright (C) 2025, Ereyna Labs Ltd. - All Rights Reserved
# @file CMakeLists.txt
# @parblock
# This file is subject to the terms and conditions defined in file 'LICENSE.md',
# which is part of this source code package.  Proprietary and confidential.
# @endparblock
# @author Dave Linten <david@ereynalabs.com>
#

# NOTE: To get awesome shit to happen system development packages are needed.
# Fedora 38+
#   sudo dnf install zlib-devel openssl-devel uuid-devel jsoncpp-devel brotli-devel doxygen graphviz
# Ubuntu 22.0+ / Debian 12+
#   apt install build-essential zlib1g-dev libssl-dev uuid-dev libjsoncpp libbrotli-dev doxygen graphviz

########################################################################################################################
# Global project variables, CMake and Compiler configuration section
########################################################################################################################

# Specify minimum CMake compatibility
cmake_minimum_required(VERSION 3.25)

# Project naming variables
set(APP_BIN_TARGET "encryptopp")
set(APP_LIB_TARGET "encryptopp-lib")
set(APP_CONFIG_TARGET "encryptopp-config")
set(APP_TEST_TARGET "encryptopp-test")
set(APP_DOC_TARGET "encryptopp-doc")

# Assign the project name
project("encryptopp" CXX)

# Print the project name using the PROJECT_NAME variable
message(STATUS "Project Name: ${PROJECT_NAME}")

# Configure C++ Compiler settings and standards
set(CMAKE_CXX_STANDARD 20)                              # Set the C++ Standard to C++20
set(CMAKE_CXX_STANDARD_REQUIRED ON)                     # Force adherence to the C++ Standards
# set(CMAKE_BUILD_TYPE debug)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++20") # -fPIC") # Force some flags for bad projects that do not implement CMake correctly
UNSET(BUILD_SHARED_LIBS)                              # Force the output of static only libraries

option(BUILD_STATIC "Use static linkage" ON)
set(BUILD_SHARED_LIBS OFF)                                   # Turn off the building and output of shared libraries

# Set SSL to use latest only
option(OPENSSL_API_COMPAT "User OpenSSL 3 only" 0x30000000L)
option(OPENSSL_NO_DEPRECATED "Set no deprecated calls to be used" ON)

# Adhere to GNU filesystem layout conventions
include(GNUInstallDirs)

# Configure GNU output folder structure
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib" CACHE PATH "Archive output dir.")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib" CACHE PATH "Library output dir.")
set(CMAKE_PDB_OUTPUT_DIRECTORY     "${CMAKE_BINARY_DIR}/bin" CACHE PATH "PDB (MSVC debug symbol)output dir.")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin" CACHE PATH "Executable/dll output dir.")

# Macro to check if C++ Header files can be included.
include(CheckIncludeFileCXX)

check_include_file_cxx(any HAS_ANY)                     # Checks and includes the header if "any" is supported
check_include_file_cxx(string_view HAS_STRING_VIEW)     # Checks and includes the header if "string_view" is supported
check_include_file_cxx(coroutine HAS_COROUTINE)         # Checks and includes the header if "coroutine" is supported

# Determine if C++20 is fully supported
if (HAS_ANY AND HAS_STRING_VIEW AND HAS_COROUTINE)
    message(STATUS "Using C++ 20")
    set(CMAKE_CXX_STANDARD 20)
elseif (HAS_ANY AND HAS_STRING_VIEW)         # otherwise rollback the C++17 standard and check again
    message(STATUS "Using C++ 17")
    set(CMAKE_CXX_STANDARD 17)
else ()                                      # C++20/17 is not supported, assume C++14
    message(STATUS "Using C++ 14")
    set(CMAKE_CXX_STANDARD 14)
endif ()

# Check if I'm running this build on an Apple, if so reassign openssl directories for library lookup.
if (APPLE)
    # brew install gcc-11 or version of choice
    # set clion compiler, set to bash terminal and alias in .bash_profile
    #   alias ll='ls -la'
    #   alias gcc='gcc-11'
    #   alias cc='gcc-11'
    #   alias g++='g++-11'
    #   alias c++='c++-11'

    # brew install openssl
    set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl")
    set(OPENSSL_LIBRARIES "/usr/local/opt/openssl/lib")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS}")
    #set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -no-pie")
    # brew install jsoncpp
    # brew install ossp-uuid
    # brew install doxygen
    # brew install brotli
    # brew install dia
    # brew install graphviz
    # brew install nodejs
    # brew install cmake
    # npm install -g @angular/cli
    # npm install -g npm@7.20.5
endif ()

########################################################################################################################
# 3rd Party Components and frameworks section
########################################################################################################################

# Turn off compiler specific extensions, as we add -std=c++20 manually to support the widest range of compilers.
set(CMAKE_CXX_EXTENSIONS OFF)

# Include the CMake macro. This module enables populating content at configure time via any method supported by the
#  ExternalProject module, and makes dependency resolution easy.  When used with FetchContent_Declare, a target is
#  created, that allows the developer to choose if the output component is a static or dynamic library.
include(FetchContent)

# Include the JsonCPP Library from GitHub.  This library handles JSON
#FetchContent_Declare(
#        jsoncpp
#        GIT_REPOSITORY https://github.com/open-source-parsers/jsoncpp.git
#        GIT_TAG master
#)

FetchContent_Declare(
        jsoncpp
        SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/libraries/jsoncpp"
)

# The jwt-cpp Library is required to handle JWT Tokens.
#option(CPP_JWT_BUILD_EXAMPLES "build examples" OFF)    # Uncomment to turn off building of examples
#option(CPP_JWT_BUILD_TESTS "build tests" OFF)          # Uncomment to turn off unit tests for this component
#FetchContent_Declare(
#        jwt-cpp
#        GIT_REPOSITORY https://github.com/Thalhammer/jwt-cpp.git
#        GIT_TAG master
#)

FetchContent_Declare(
        jwt-cpp
        SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/libraries/jwt-cpp"
)

option(BUILD_STATIC "Use static linkage" ON)    # Output a static library
set(BUILD_SHARED_LIBS OFF)                      # Turn off the building and output of shared libraries

# Include ArgParse and Magic Enum for application command line parsing.
option(MAGIC_ENUM_OPT_BUILD_EXAMPLES "Build magic_enum examples" OFF)
option(MAGIC_ENUM_OPT_BUILD_TESTS "Build and perform magic_enum tests" OFF)
# option(MAGIC_ENUM_OPT_INSTALL "Generate and install magic_enum target" ${IS_TOPLEVEL_PROJECT})

#FetchContent_Declare(
#        magic_enum
#        GIT_REPOSITORY https://github.com/Neargye/magic_enum.git
#        GIT_TAG v0.9.5
#)

FetchContent_Declare(
        magic_enum
        SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/libraries/magic_enum"
)


option(ARGPARSE_BUILD_EXAMPLES "Build argparse examples" OFF)
option(ARGPARSE_BUILD_TESTS "Build and run argparse tests" OFF)

#FetchContent_Declare(
#        argparse
#        GIT_REPOSITORY https://github.com/morrisfranken/argparse.git
#        GIT_TAG master
#)

FetchContent_Declare(
        argparse
        SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/libraries/argparse"
)

# Now we make JsonCPP, jwt-cpp and Drogon libraries and frameworks available to CMake for project to include in
FetchContent_MakeAvailable(magic_enum argparse jsoncpp jwt-cpp)

########################################################################################################################
# Project core section
########################################################################################################################

if (CMAKE_BUILD_TYPE MATCHES Debug)
    add_definitions(-DDEBUG)
endif()

# Always architect your project in terms of a library, that is then wrapped with an executable.
# Static linkage means we can now incorporate the same library into other products under one binary, or chose to change
#  the linkage to dynamic, and share the library between executables or other libraries.
add_library(${APP_LIB_TARGET} STATIC ${CMAKE_CURRENT_SOURCE_DIR}/main-lib.cc)

## Include directories for the library consumers
#target_include_directories(${APP_LIB_TARGET} PUBLIC
#        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
#        $<INSTALL_INTERFACE:include>
#)
message("*** JSON SOURCE DIR = ${jsoncpp_SOURCE_DIR}")
# Configure global include directories.  Headers within these directories can now be parsed by the compiler and IDE
target_include_directories(${APP_LIB_TARGET}
        PUBLIC
        ${jsoncpp_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/models
        ${CMAKE_CURRENT_SOURCE_DIR}/controllers
        ${CMAKE_CURRENT_SOURCE_DIR}/helpers)

# Link the project library to the libraries make available in FetchContent_MakeAvailable
target_link_libraries(${APP_LIB_TARGET} PUBLIC magic_enum argparse jsoncpp jwt-cpp)

# Assign all the controller source files from ./controllers
set(CTL_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/controllers/AesCtrl.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/controllers/AesCtrlBase.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/controllers/Base64Ctrl.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/controllers/Base64CtrlBase.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/controllers/JwtCtrl.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/controllers/JwtCtrlBase.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/controllers/RsaCtrl.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/controllers/RsaCtrlBase.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/controllers/ShaCtrl.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/controllers/ShaCtrlBase.cc
)

# Assign all the model source files from ./models
set(MODEL_SRC
        #        ${CMAKE_CURRENT_SOURCE_DIR}/models/Aes.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/models/JwtPayload.cc
)

# Assign all the helper source files from ./helpers
set(HELPER_SRC
        #        ${CMAKE_CURRENT_SOURCE_DIR}/helpers/Aes.cc
)



# Add all the sources configured above to the project library target.
target_sources(${APP_LIB_TARGET}
        PUBLIC
        ${CTL_SRC}
        ${MODEL_SRC}
        ${HELPER_SRC})

# Create a target for copying all the UI Web resources from www source to www destination.
add_custom_target(${APP_CONFIG_TARGET} ALL
        COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/etc/ssl/private
        COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/etc/ssl/certs
        COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/etc/${APP_BIN_TARGET}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/var/lib/${APP_BIN_TARGET}/data
        #        COMMAND npm install --omit=dev --prefix ${CMAKE_SOURCE_DIR}/www react react-dom @coreui/coreui
        #        COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_SOURCE_DIR}/www/node_modules/react/umd ${CMAKE_SOURCE_DIR}/www/react
        #        COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_SOURCE_DIR}/www/node_modules/react-dom/umd ${CMAKE_SOURCE_DIR}/www/react
        #        COMMAND ${CMAKE_COMMAND} -E rm -f ${CMAKE_SOURCE_DIR}/www/package.json ${CMAKE_SOURCE_DIR}/www/package-lock.json
        #        COMMAND ${CMAKE_COMMAND} -E rm -rf ${CMAKE_SOURCE_DIR}/www/node_modules
        #        COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_SOURCE_DIR}/www ${CMAKE_BINARY_DIR}/srv/www # Remove if Angular or similar framework is used to build the output.
        COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/var/log/${APP_BIN_TARGET}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/var/tmp/${APP_BIN_TARGET}/scripts
        # COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/config.json ${CMAKE_BINARY_DIR}/etc/${APP_BIN_TARGET}/config.json
        # COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_SOURCE_DIR}/scripts ${CMAKE_BINARY_DIR}/var/tmp/${APP_BIN_TARGET}/scripts
        COMMAND openssl req -x509 -newkey rsa:4096 -nodes -keyout ${CMAKE_BINARY_DIR}/etc/ssl/private/server.key -out ${CMAKE_BINARY_DIR}/etc/ssl/certs/server.crt -days 365 -subj "/C=GB/ST=London/L=London/O=Ereyna Labs Ltd../OU=Self Signed Temporary/CN=localhost"
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        COMMENT "Generating and applying system configuration...")

# Add the executable binary wrapper for the project target library
add_executable(${APP_BIN_TARGET} ${CMAKE_CURRENT_SOURCE_DIR}/main.cc)

# Make the APP_SYSTEM_CONFIGURE a dependency of the APP_LIB_TARGET, so that when the library is built, APP_SYSTEM_CONFIGURE is
#  triggered to ensure the system path structures and certificates, scripts and other things are in place.
add_dependencies(${APP_LIB_TARGET} ${APP_CONFIG_TARGET})

# Link the project library to the executable wrapper
target_link_libraries(${APP_BIN_TARGET} PRIVATE ${APP_LIB_TARGET})

# Add the library header to the executable library wrapper, so the wrapper has an interface to call the library
target_include_directories(${APP_BIN_TARGET} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

########################################################################################################################
# Project documentation section
########################################################################################################################

# Check if DoxyGen is configured, if so, create a documentation target
find_package(Doxygen)
if(Doxygen_FOUND)
    add_subdirectory(docs)
else()
    message(STATUS "Doxygen not found, not building docs")
endif()

########################################################################################################################
# Project test section
########################################################################################################################

# Store value for the last change back to see if consumer requires this project to be tested.
set(ORIGINAL_BUILD_TESTING BUILD_TESTING)

# Turn and force the global off
set(BUILD_TESTING OFF CACHE INTERNAL "" FORCE)
# Enable testing for the project
#enable_testing()
add_subdirectory(tests)

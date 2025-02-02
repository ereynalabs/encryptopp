/**
 * @copyright Copyright (C) 2025, Ereyna Labs Ltd. - All Rights Reserved
 * @file secure_string.h
 * @parblock
 * This file is subject to the terms and conditions defined in file 'LICENSE.md',
 * which is part of this source code package.  Proprietary and confidential.
 * @endparblock
 * @author Dave Linten <david@ereynalabs.com>
 */


/**
 * TODO:  See if this can be marketed on its own, as this class prevents even debuggers from peeking memory.
 */

#pragma once

#include <string>
#include <memory>
#include <limits>
#include <openssl/evp.h>
#include <vector>

namespace encryptopp::string {

    template<typename T>
    struct zallocator {
        using value_type = T;
        using pointer = value_type*;
        using const_pointer = const value_type*;
        using reference = value_type&;
        using const_reference = const value_type&;
        using size_type = std::size_t;
        using difference_type = std::ptrdiff_t;

        static pointer address(reference v) { return &v; }

        static const_pointer address(const_reference v) { return &v; }

        static pointer allocate(size_type n, const void *hint = nullptr) {
            if (n > std::numeric_limits<size_type>::max() / sizeof(T))
                throw std::bad_alloc();
            return static_cast<pointer> (::operator new(n * sizeof(value_type)));
        }

        static void deallocate(pointer p, size_type n) {
            OPENSSL_cleanse(p, n * sizeof(T));
            ::operator delete(p);
        }

        [[nodiscard]] static size_type max_size() {
            return std::numeric_limits<size_type>::max() / sizeof(T);
        }

        template<typename U>
        struct rebind {
            using other = zallocator<U>;
        };

        static void construct(pointer ptr, const T &val) {
            new(static_cast<T *>(ptr)) T(val);
        }

        static void destroy(pointer ptr) {
            static_cast<T *>(ptr)->~T();
        }

#if __cpluplus >= 201103L
        template<typename U, typename... Args>
    void construct (U* ptr, Args&&  ... args) {
        ::new (static_cast<void*> (ptr) ) U (std::forward<Args> (args)...);
    }

    template<typename U>
    void destroy(U* ptr) {
        ptr->~U();
    }
#endif
    };

    // Equality operator for zallocator
    template<typename T>
    bool operator==(const zallocator<T>&, const zallocator<T>&) {
        return true;
    }

    template<typename T>
    bool operator!=(const zallocator<T>& lhs, const zallocator<T>& rhs) {
        return !(lhs == rhs);
    }

    // Change type here to use secure strings or if debugging is require, plain strings.
    // Definition DEBUG is set in CMakeLists.txt based on the IDE Requested Build Type
#ifdef DEBUG
    using secure_string = std::string;
#else
    using secure_string = std::basic_string<char, std::char_traits<char>, zallocator<char> >;
#endif

}
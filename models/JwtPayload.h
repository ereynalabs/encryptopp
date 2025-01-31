/**
 * @copyright Copyright (C) 2024, Ereyna Labs Ltd. - All Rights Reserved
 * @file JwtPayload.h
 * @parblock
 * This file is subject to the terms and conditions defined in file 'LICENSE.md',
 * which is part of this source code package.  Proprietary and confidential.
 * @endparblock
 * @author Dave Linten <david@ereynalabs.com>
 */

#pragma once

#include <json/json.h>
#include <string>
#include <memory>

namespace models {
    class JwtPayload {
    public:
        using unix_time_stamp_t = int64_t;

        /**
         * @brief constructor
         * @param pJson The json object to construct a new instance.
         */
        explicit JwtPayload(const Json::Value &pJson) noexcept(false);

        JwtPayload() = default;

        /**
        The "iss" (issuer) claim identifies the principal that issued the
        JWT.  The processing of this claim is generally application specific.
        The "iss" value is a case-sensitive string containing a StringOrURI
        value.  Use of this claim is OPTIONAL.
        */
        [[nodiscard]] const std::string &getValueOfIss() const noexcept;

        [[nodiscard]] const std::shared_ptr<std::string> &getIss() const noexcept;

        void setIss(const std::string &value) noexcept;

        void setIss(std::string &&value) noexcept;

        /**
        The "sub" (subject) claim identifies the principal that is the
        subject of the JWT.  The claims in a JWT are normally statements
        about the subject.  The subject value MUST either be scoped to be
        locally unique in the context of the issuer or be globally unique.
        The processing of this claim is generally application specific.  The
        "sub" value is a case-sensitive string containing a StringOrURI
        value.  Use of this claim is OPTIONAL.
        */
        [[nodiscard]] const std::string &getValueOfSub() const noexcept;

        [[nodiscard]] const std::shared_ptr<std::string> &getSub() const noexcept;

        void setSub(const std::string &value) noexcept;

        void setSub(std::string &&value) noexcept;

        /**
        The "aud" (audience) claim identifies the recipients that the JWT is
        intended for.  Each principal intended to process the JWT MUST
        identify itself with a value in the audience claim.  If the principal
        processing the claim does not identify itself with a value in the
        "aud" claim when this claim is present, then the JWT MUST be
        rejected.  In the general case, the "aud" value is an array of case-
        sensitive strings, each containing a StringOrURI value.  In the
        special case when the JWT has one audience, the "aud" value MAY be a
        single case-sensitive string containing a StringOrURI value.  The
        interpretation of audience values is generally application specific.
        Use of this claim is OPTIONAL.
        */
        [[nodiscard]] const std::string &getValueOfAud() const noexcept;

        [[nodiscard]] const std::shared_ptr<std::string> &getAud() const noexcept;

        void setAud(const std::string &value) noexcept;

        void setAud(std::string &&value) noexcept;

        /**
        The "exp" (expiration time) claim identifies the expiration time on
        or after which the JWT MUST NOT be accepted for processing.  The
        processing of the "exp" claim requires that the current date/time
        MUST be before the expiration date/time listed in the "exp" claim.
        Implementers MAY provide for some small leeway, usually no more than
        a few minutes, to account for clock skew.  Its value MUST be a number
        containing a NumericDate value.  Use of this claim is OPTIONAL.
        */
        [[nodiscard]] const unix_time_stamp_t &getValueOfExp() const noexcept;

        [[nodiscard]] const std::shared_ptr<unix_time_stamp_t> &getExp() const noexcept;

        void setExp(const unix_time_stamp_t &value) noexcept;

        void setExp(unix_time_stamp_t &&value) noexcept;

        void setExpNow() noexcept;

        /**
        The "nbf" (not before) claim identifies the time before which the JWT
        MUST NOT be accepted for processing.  The processing of the "nbf"
        claim requires that the current date/time MUST be after or equal to
        the not-before date/time listed in the "nbf" claim.  Implementers MAY
        provide for some small leeway, usually no more than a few minutes, to
        account for clock skew.  Its value MUST be a number containing a
        NumericDate value.  Use of this claim is OPTIONAL.
        */
        [[nodiscard]] const unix_time_stamp_t &getValueOfNbf() const noexcept;

        [[nodiscard]] const std::shared_ptr<unix_time_stamp_t> &getNbf() const noexcept;

        void setNbf(const unix_time_stamp_t &value) noexcept;

        void setNbf(unix_time_stamp_t &&value) noexcept;

        void setNbfNow() noexcept;

        /**
        The "iat" (issued at) claim identifies the time at which the JWT was
        issued.  This claim can be used to determine the age of the JWT.  Its
        value MUST be a number containing a NumericDate value.  Use of this
        claim is OPTIONAL.
        */
        [[nodiscard]] const unix_time_stamp_t &getValueOfIat() const noexcept;

        [[nodiscard]] const std::shared_ptr<unix_time_stamp_t> &getIat() const noexcept;

        void setIat(const unix_time_stamp_t &value) noexcept;

        void setIat(unix_time_stamp_t &&value) noexcept;

        void setIatNow() noexcept;

        /**
        The "jti" (JWT ID) claim provides a unique identifier for the JWT.
        The identifier value MUST be assigned in a manner that ensures that
        there is a negligible probability that the same value will be
        accidentally assigned to a different data object; if the application
        uses multiple issuers, collisions MUST be prevented among values
        produced by different issuers as well.  The "jti" claim can be used
        to prevent the JWT from being replayed.  The "jti" value is a case-
        sensitive string.  Use of this claim is OPTIONAL.
        */
        [[nodiscard]] const std::string &getValueOfJti() const noexcept;

        [[nodiscard]] const std::shared_ptr<std::string> &getJti() const noexcept;

        void setJti(const std::string &value) noexcept;

        void setJti(std::string &&value) noexcept;

        /**
        The "data" claim provides space for storing small amounts of data.
        This claim should not be over used, so as to break the limitations of
        header sizes, or other OAuth limitations.  It is best to encrypt this
        data.  Use of this claim is OPTIONAL.
        */
        [[nodiscard]] const std::string &getValueOfData() const noexcept;

        [[nodiscard]] const std::shared_ptr<std::string> &getData() const noexcept;

        void setData(const std::string &value) noexcept;

        void setData(std::string &&value) noexcept;

        [[nodiscard]] Json::Value toJson() const;

        [[nodiscard]] std::string toString() const;

    private:
        std::shared_ptr<std::string> iss_;
        std::shared_ptr<std::string> sub_;
        std::shared_ptr<std::string> aud_;
        std::shared_ptr<unix_time_stamp_t> exp_;
        std::shared_ptr<unix_time_stamp_t> nbf_;
        std::shared_ptr<unix_time_stamp_t> iat_;
        std::shared_ptr<std::string> jti_;
        std::shared_ptr<std::string> data_;
        bool dirtyFlag_[8] = {false};
    };
}

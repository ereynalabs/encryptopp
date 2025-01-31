/**
 * @copyright Copyright (C) 2024, Ereyna Labs Ltd. - All Rights Reserved
 * @file JwtPayload.cc
 * @parblock
 * This file is subject to the terms and conditions defined in file 'LICENSE.md',
 * which is part of this source code package.  Proprietary and confidential.
 * @endparblock
 * @author Dave Linten <david@ereynalabs.com>
 */

#include "JwtPayload.h"

#include <chrono>
#include <memory>

namespace models {
    JwtPayload::JwtPayload(const Json::Value &pJson) noexcept(false) {
        if (pJson.isMember("iss")) {
            dirtyFlag_[0] = true;
            if (!pJson["iss"].isNull()) {
                iss_ = std::make_shared<std::string>(pJson["iss"].asString());
            }
        }

        if (pJson.isMember("sub")) {
            dirtyFlag_[1] = true;
            if (!pJson["sub"].isNull()) {
                sub_ = std::make_shared<std::string>(pJson["sub"].asString());
            }
        }

        if (pJson.isMember("aud")) {
            dirtyFlag_[2] = true;
            if (!pJson["aud"].isNull()) {
                aud_ = std::make_shared<std::string>(pJson["aud"].asString());
            }
        }

        if (pJson.isMember("exp")) {
            dirtyFlag_[3] = true;
            if (!pJson["exp"].isNull()) {
                exp_ = std::make_shared<unix_time_stamp_t>(pJson["exp"].asInt64());
            }
        }

        if (pJson.isMember("nbf")) {
            dirtyFlag_[4] = true;
            if (!pJson["nbf"].isNull()) {
                nbf_ = std::make_shared<unix_time_stamp_t>(pJson["nbf"].asInt64());
            }
        }

        if (pJson.isMember("iat")) {
            dirtyFlag_[5] = true;
            if (!pJson["iat"].isNull()) {
                iat_ = std::make_shared<unix_time_stamp_t>(pJson["iat"].asInt64());
            }
        }

        if (pJson.isMember("jti")) {
            dirtyFlag_[6] = true;
            if (!pJson["jti"].isNull()) {
                jti_ = std::make_shared<std::string>(pJson["jti"].asString());
            }
        }

        if (pJson.isMember("data")) {
            dirtyFlag_[7] = true;
            if (!pJson["data"].isNull()) {
                data_ = std::make_shared<std::string>(pJson["data"].asString());
            }
        }
    }

    const std::string &JwtPayload::getValueOfIss() const noexcept {
        const static std::string defaultValue = std::string();
        if (iss_)
            return *iss_;
        return defaultValue;
    }

    const std::shared_ptr<std::string> &JwtPayload::getIss() const noexcept {
        return iss_;
    }

    void JwtPayload::setIss(const std::string &value) noexcept {
        iss_ = std::make_shared<std::string>(value);
        dirtyFlag_[0] = true;
    }

    void JwtPayload::setIss(std::string &&value) noexcept {
        iss_ = std::make_shared<std::string>(std::move(value));
        dirtyFlag_[0] = true;
    }

    const std::string &JwtPayload::getValueOfSub() const noexcept {
        const static std::string defaultValue = std::string();
        if (sub_)
            return *sub_;
        return defaultValue;
    }

    const std::shared_ptr<std::string> &JwtPayload::getSub() const noexcept {
        return sub_;
    }

    void JwtPayload::setSub(const std::string &value) noexcept {
        sub_ = std::make_shared<std::string>(value);
        dirtyFlag_[1] = true;
    }

    void JwtPayload::setSub(std::string &&value) noexcept {
        sub_ = std::make_shared<std::string>(std::move(value));
        dirtyFlag_[1] = true;
    }

    const std::string &JwtPayload::getValueOfAud() const noexcept {
        const static std::string defaultValue = std::string();
        if (aud_)
            return *aud_;
        return defaultValue;
    }

    const std::shared_ptr<std::string> &JwtPayload::getAud() const noexcept {
        return aud_;
    }

    void JwtPayload::setAud(const std::string &value) noexcept {
        aud_ = std::make_shared<std::string>(value);
        dirtyFlag_[2] = true;
    }

    void JwtPayload::setAud(std::string &&value) noexcept {
        aud_ = std::make_shared<std::string>(std::move(value));
        dirtyFlag_[2] = true;
    }

    const JwtPayload::unix_time_stamp_t &JwtPayload::getValueOfExp() const noexcept {
        static constexpr unix_time_stamp_t default_value = 0;
        if (exp_)
            return *exp_;
        return default_value;
    }

    const std::shared_ptr<JwtPayload::unix_time_stamp_t> &JwtPayload::getExp() const noexcept {
        return exp_;
    }

    void JwtPayload::setExp(const unix_time_stamp_t &value) noexcept {
        exp_ = std::make_shared<unix_time_stamp_t>(value);
        dirtyFlag_[3] = true;
    }

    void JwtPayload::setExpNow() noexcept {
        exp_ = std::make_shared<unix_time_stamp_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).
            count());
        dirtyFlag_[3] = true;
    }

    void JwtPayload::setExp(unix_time_stamp_t &&value) noexcept {
        exp_ = std::make_shared<unix_time_stamp_t>(value);
        dirtyFlag_[3] = true;
    }

    const JwtPayload::unix_time_stamp_t &JwtPayload::getValueOfNbf() const noexcept {
        static constexpr unix_time_stamp_t default_value = 0;
        if (nbf_)
            return *nbf_;
        return default_value;
    }

    const std::shared_ptr<JwtPayload::unix_time_stamp_t> &JwtPayload::getNbf() const noexcept {
        return nbf_;
    }

    void JwtPayload::setNbf(const unix_time_stamp_t &value) noexcept {
        nbf_ = std::make_shared<unix_time_stamp_t>(value);
        dirtyFlag_[4] = true;
    }

    void JwtPayload::setNbf(unix_time_stamp_t &&value) noexcept {
        nbf_ = std::make_shared<unix_time_stamp_t>(value);
        dirtyFlag_[4] = true;
    }

    void JwtPayload::setNbfNow() noexcept {
        nbf_ = std::make_shared<unix_time_stamp_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).
            count());
        dirtyFlag_[4] = true;
    }

    const JwtPayload::unix_time_stamp_t &JwtPayload::getValueOfIat() const noexcept {
        static constexpr unix_time_stamp_t default_value = 0;
        if (iat_)
            return *iat_;
        return default_value;
    }

    const std::shared_ptr<JwtPayload::unix_time_stamp_t> &JwtPayload::getIat() const noexcept {
        return iat_;
    }

    void JwtPayload::setIat(const unix_time_stamp_t &value) noexcept {
        iat_ = std::make_shared<unix_time_stamp_t>(value);
        dirtyFlag_[5] = true;
    }

    void JwtPayload::setIat(unix_time_stamp_t &&value) noexcept {
        iat_ = std::make_shared<unix_time_stamp_t>(value);
        dirtyFlag_[5] = true;
    }

    void JwtPayload::setIatNow() noexcept {
        iat_ = std::make_shared<unix_time_stamp_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).
            count());
        dirtyFlag_[5] = true;
    }

    const std::string &JwtPayload::getValueOfJti() const noexcept {
        const static std::string defaultValue = std::string();
        if (jti_)
            return *jti_;
        return defaultValue;
    }

    const std::shared_ptr<std::string> &JwtPayload::getJti() const noexcept {
        return jti_;
    }

    void JwtPayload::setJti(const std::string &value) noexcept {
        jti_ = std::make_shared<std::string>(value);
        dirtyFlag_[6] = true;
    }

    void JwtPayload::setJti(std::string &&value) noexcept {
        jti_ = std::make_shared<std::string>(std::move(value));
        dirtyFlag_[6] = true;
    }


    const std::string &JwtPayload::getValueOfData() const noexcept {
        const static std::string defaultValue = std::string();
        if (data_)
            return *data_;
        return defaultValue;
    }

    const std::shared_ptr<std::string> &JwtPayload::getData() const noexcept {
        return data_;
    }

    void JwtPayload::setData(const std::string &value) noexcept {
        data_ = std::make_shared<std::string>(value);
        dirtyFlag_[7] = true;
    }

    void JwtPayload::setData(std::string &&value) noexcept {
        data_ = std::make_shared<std::string>(std::move(value));
        dirtyFlag_[7] = true;
    }

    Json::Value JwtPayload::toJson() const {
        Json::Value ret;

        ret["iss"] = getIss() ? getValueOfIss() : "";
        ret["sub"] = getSub() ? getValueOfSub() : "";
        ret["aud"] = getAud() ? getValueOfAud() : "";
        ret["exp"] = getExp() ? getValueOfExp() : 0;
        ret["nbf"] = getNbf() ? getValueOfNbf() : 0;
        ret["iat"] = getIat() ? getValueOfIat() : 0;
        ret["jti"] = getJti() ? getValueOfJti() : "";
        ret["data"] = getData() ? getValueOfData() : "";

        return ret;
    }

    std::string JwtPayload::toString() const {
        Json::FastWriter fast_writer;
        fast_writer.omitEndingLineFeed();
        return fast_writer.write(toJson());
    }
}

// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/session_parameters.hpp"

#include "../include/message_serializer.hpp"
#include "../include/message_deserializer.hpp"
#include "../../crypto/asymmetric/include/asymmetric_crypto_private.hpp"
#include "../../crypto/asymmetric/include/asymmetric_crypto_public.hpp"
#include "../../crypto/random/include/random.hpp"
#include "../../crypto/symmetric/include/aes_ccm.hpp"
#include "../../crypto/symmetric/include/aes_gcm.hpp"
#include "../../crypto/symmetric/include/chacha20_poly1305.hpp"

// ======
#include "../../logging/include/logger.hpp"
#include <vsomeip/constants.hpp>
// ======

namespace vsomeip {

static size_t get_key_length(crypto_algorithm _algorithm) {
    switch (_algorithm) {
        case crypto_algorithm::CA_CHACHA20_POLY1305_256:
            return chacha20_poly1305::KEY_LENGTH;

        case crypto_algorithm::CA_AES_GCM_128:
            return aes_gcm<aes_key_length::AES_128>::KEY_LENGTH;
        case crypto_algorithm::CA_AES_GCM_256:
            return aes_gcm<aes_key_length::AES_256>::KEY_LENGTH;

        case crypto_algorithm::CA_AES_CCM_128:
            return aes_ccm<aes_key_length::AES_128>::KEY_LENGTH;
        case crypto_algorithm::CA_AES_CCM_256:
            return aes_ccm<aes_key_length::AES_256>::KEY_LENGTH;

        case crypto_algorithm::CA_INVALID:
        case crypto_algorithm::CA_NULL:
            return 0;
    }
    return 0;
}

// ====================================
/*
session_parameters::session_parameters(crypto_algorithm_packed _algorithm_packed, random &_random,
                                       std::uint32_t _buffer_shrink_threshold)
        : algorithm_packed_(_algorithm_packed),
          key_(_random.randomize(get_key_length(get_crypto_algorithm()))),
          instance_id_(PROVIDER_INSTANCE_ID), next_instance_id_(PROVIDER_INSTANCE_ID + 1),
          valid_(_algorithm_packed.is_valid_combination() &&
                 (security_level::SL_NOSEC == get_security_level() || !key_.empty()) &&
                 initialize_serializers(_buffer_shrink_threshold) &&
                 deserializer_->add_allowed_peer(PROVIDER_INSTANCE_ID)) {

}

session_parameters::session_parameters(crypto_algorithm_packed _algorithm_packed,
                                       const std::vector<byte_t> &_encrypted_key,
                                       crypto_instance_t _instance_id,
                                       const std::shared_ptr<asymmetric_crypto_private> &_private_key,
                                       uint32_t _buffer_shrink_threshold)
        : algorithm_packed_(_algorithm_packed),
          key_(_private_key && security_level::SL_NOSEC != get_security_level()
               ? _private_key->decipher(_encrypted_key.data(), _encrypted_key.size())
               : secure_vector<byte_t>()),
          instance_id_(_instance_id),
          valid_(_algorithm_packed.is_valid_combination() && PROVIDER_INSTANCE_ID != _instance_id &&
                 (security_level::SL_NOSEC == get_security_level() || !key_.empty()) &&
                 initialize_serializers(_buffer_shrink_threshold) &&
                 deserializer_->add_allowed_peer(PROVIDER_INSTANCE_ID)) {
}
*/
session_parameters::session_parameters(crypto_algorithm_packed _algorithm_packed, random &_random,
                                       std::uint32_t _buffer_shrink_threshold)  // 서버 session_parameter
        : algorithm_packed_(_algorithm_packed),
          dk1_(_random.randomize(get_key_length(get_crypto_algorithm()))),
          dk2_(_random.randomize(get_key_length(get_crypto_algorithm()))),
          uk1_(_random.randomize(get_key_length(get_crypto_algorithm()))),
          uk2_(_random.randomize(get_key_length(get_crypto_algorithm()))),
          instance_id_(PROVIDER_INSTANCE_ID), next_instance_id_(PROVIDER_INSTANCE_ID + 1),
          valid_(_algorithm_packed.is_valid_combination() &&
                 (security_level::SL_NOSEC == get_security_level() || (!dk1_.empty() && !dk2_.empty() && !uk1_.empty() && !uk2_.empty())) &&
                 initialize_serializers(_buffer_shrink_threshold) &&
                 deserializer_->add_allowed_peer(PROVIDER_INSTANCE_ID)) {
    VSOMEIP_WARNING << "session_parameters::session_parameters1";

}
/*
session_parameters::session_parameters(crypto_algorithm_packed _algorithm_packed,
                                       const std::vector<byte_t> &_encrypted_key,  // 암호화된 도메인 키
                                       crypto_instance_t _instance_id,
                                       const std::shared_ptr<asymmetric_crypto_private> &_private_key,
                                       uint32_t _buffer_shrink_threshold)
        : algorithm_packed_(_algorithm_packed),
          key_(_private_key && security_level::SL_NOSEC != get_security_level()
               ? _private_key->decipher(_encrypted_key.data(), _encrypted_key.size())
               : secure_vector<byte_t>()),
          instance_id_(_instance_id),
          valid_(_algorithm_packed.is_valid_combination() && PROVIDER_INSTANCE_ID != _instance_id &&
                 (security_level::SL_NOSEC == get_security_level() || !key_.empty()) &&
                 initialize_serializers(_buffer_shrink_threshold) &&
                 deserializer_->add_allowed_peer(PROVIDER_INSTANCE_ID)) {
    VSOMEIP_WARNING << "session_parameters::session_parameters2";
}
*/
session_parameters::session_parameters(crypto_algorithm_packed _algorithm_packed,
                                       const std::vector<byte_t> &_encrypted_key,  // 암호화된 도메인 키
                                       const std::vector<byte_t> &_encrypted_update_key,  // 암호화된 업데이트 키
                                       crypto_instance_t _instance_id,
                                       const std::shared_ptr<asymmetric_crypto_private> &_private_key,
                                       uint32_t _buffer_shrink_threshold)  // 클라이언트 session_parameter
        : algorithm_packed_(_algorithm_packed),
          key_(_private_key && security_level::SL_NOSEC != get_security_level()
               ? _private_key->decipher(_encrypted_key.data(), _encrypted_key.size())
               : secure_vector<byte_t>()),
          uk_(_private_key && security_level::SL_NOSEC != get_security_level()    // 클라이언트가 받을 uk_
               ? _private_key->decipher(_encrypted_update_key.data(), _encrypted_update_key.size())
               : secure_vector<byte_t>()),
          instance_id_(_instance_id),
          valid_(_algorithm_packed.is_valid_combination() && PROVIDER_INSTANCE_ID != _instance_id &&
                 (security_level::SL_NOSEC == get_security_level() || !key_.empty()) &&
                 initialize_serializers(_buffer_shrink_threshold) &&
                 deserializer_->add_allowed_peer(PROVIDER_INSTANCE_ID)) {
    VSOMEIP_WARNING << "session_parameters::session_parameters2";
}
// ====================================

// ===
void set_domain_key() {
    key_ = key;
}
// ===

security_level session_parameters::get_security_level() const {
    return algorithm_packed_.security_level_;
}

crypto_algorithm session_parameters::get_crypto_algorithm() const {
    return algorithm_packed_.crypto_algorithm_;
}

// =================================================
/*
const std::shared_ptr<message_serializer> &session_parameters::get_serializer() const {
    return serializer_;
}
*/
const std::shared_ptr<message_serializer> &session_parameters::get_serializer(byte_t domain_num_) const {
    VSOMEIP_WARNING << "session_parameters::get_serializer";
    if (domain_num_ == 10) {
        VSOMEIP_WARNING << "        get_serializer 10";
        return serializer1_;
    }
    else if (domain_num_ == 20) {
        VSOMEIP_WARNING << "        get_serializer 20";
        return serializer2_;
    }
    VSOMEIP_WARNING << "        can't get serializer";
    return serializer1_;
}
// =================================================
const std::shared_ptr<message_deserializer> &session_parameters::get_deserializer() const {
    return deserializer_;
}

const std::shared_ptr<message_deserializer> &session_parameters::get_uk_deserializer() const {
    return uk_deserializer_;
}


crypto_instance_t session_parameters::get_next_instance_id() {
    std::lock_guard<std::mutex> its_mutex(next_instance_id_mutex_);
    if (is_provider() && is_valid() && INVALID_INSTANCE_ID != next_instance_id_) {
        deserializer_->add_allowed_peer(next_instance_id_);
        return next_instance_id_++;
    }

    return INVALID_INSTANCE_ID;
}

// =================================
/*
std::vector<byte_t>
session_parameters::get_encrypted_key(const std::shared_ptr<asymmetric_crypto_public> &_peer_public_key) const {

    std::vector<byte_t> encrypted_key;
    if (is_provider() && is_valid() && _peer_public_key) {
        _peer_public_key->encipher(key_.data(), key_.size(), encrypted_key);
    }
    return encrypted_key;
}
*/
std::vector<byte_t>
session_parameters::get_encrypted_key(const std::shared_ptr<asymmetric_crypto_public> &_peer_public_key, byte_t _domain_num) const {  // 암호화된 도메인 키를 가져온다. 여기서 파라미터로 domain_num을 추가했음
    VSOMEIP_WARNING << "<session_parameters::get_encrypted_key> _domain_num is " << (int)_domain_num;  // 파라미터로 받아온 도메인 번호를 출력함

    std::vector<byte_t> encrypted_key;
    if (is_provider() && is_valid() && _peer_public_key && _domain_num == 10) {  // 받아온 도메인 번호가 10이라면 (도메인1이라면)
	VSOMEIP_INFO << "domain num is " << (int)_domain_num; 
        _peer_public_key->encipher(dk1_.data(), dk1_.size(), encrypted_key);  // 도메인1의 대칭키인 dk_1을 peer_public_key(클라이언트의 공개키)로 암호화한다.
    }
    else if (is_provider() && is_valid() && _peer_public_key && _domain_num == 20) {
        _peer_public_key->encipher(dk2_.data(), dk2_.size(), encrypted_key);
	VSOMEIP_INFO << "domain num is " << (int)_domain_num;
    }
    else {
        VSOMEIP_ERROR << "Failed to get encrypted key";
    }
    return encrypted_key;
}


std::vector<byte_t>
session_parameters::get_encrypted_update_key(const std::shared_ptr<asymmetric_crypto_public> &_peer_public_key, byte_t _domain_num) const {  // uk_를 암호하해서 return하는 단계
    VSOMEIP_WARNING << "<session_parameters::get_encrypted_key> _domain_num is " << (int)_domain_num;

    std::vector<byte_t> encrypted_key;
    if (is_provider() && is_valid() && _peer_public_key && _domain_num == 10) {
	VSOMEIP_INFO << "domain num is " << (int)_domain_num;
        _peer_public_key->encipher(uk1_.data(), uk1_.size(), encrypted_key);
    }
    else if (is_provider() && is_valid() && _peer_public_key && _domain_num == 20) {
        _peer_public_key->encipher(uk2_.data(), uk2_.size(), encrypted_key);
	VSOMEIP_INFO << "domain num is " << (int)_domain_num;
    }
    else {
        VSOMEIP_ERROR << "Failed to get encrypted key";
    }
    return encrypted_key;
}
// =================================

bool session_parameters::is_provider() const {
    return PROVIDER_INSTANCE_ID == instance_id_;
}

bool session_parameters::is_valid() const {
    return valid_;
}

// ===============================
/*
std::unique_ptr<mac_algorithm> session_parameters::get_mac_algorithm() const {
    switch (get_crypto_algorithm()) {
        case crypto_algorithm::CA_CHACHA20_POLY1305_256:
            return std::unique_ptr<mac_algorithm>(new chacha20_poly1305(key_, instance_id_));

        case crypto_algorithm::CA_AES_GCM_128:
            return std::unique_ptr<mac_algorithm>(new aes_gcm<aes_key_length::AES_128>(key_, instance_id_));
        case crypto_algorithm::CA_AES_GCM_256:
            return std::unique_ptr<mac_algorithm>(new aes_gcm<aes_key_length::AES_256>(key_, instance_id_));

        case crypto_algorithm::CA_AES_CCM_128:
            return std::unique_ptr<mac_algorithm>(new aes_ccm<aes_key_length::AES_128>(key_, instance_id_));
        case crypto_algorithm::CA_AES_CCM_256:
            return std::unique_ptr<mac_algorithm>(new aes_ccm<aes_key_length::AES_256>(key_, instance_id_));

        case crypto_algorithm::CA_INVALID:
        case crypto_algorithm::CA_NULL:
            return std::unique_ptr<mac_algorithm>();
    }
    return std::unique_ptr<mac_algorithm>();
}

std::unique_ptr<aead_algorithm> session_parameters::get_aead_algorithm() const {
    switch (get_crypto_algorithm()) {
        case crypto_algorithm::CA_CHACHA20_POLY1305_256:
            return std::unique_ptr<aead_algorithm>(new chacha20_poly1305(key_, instance_id_));

        case crypto_algorithm::CA_AES_GCM_128:
            return std::unique_ptr<aead_algorithm>(new aes_gcm<aes_key_length::AES_128>(key_, instance_id_));
        case crypto_algorithm::CA_AES_GCM_256:
            return std::unique_ptr<aead_algorithm>(new aes_gcm<aes_key_length::AES_256>(key_, instance_id_));

        case crypto_algorithm::CA_AES_CCM_128:
            return std::unique_ptr<aead_algorithm>(new aes_ccm<aes_key_length::AES_128>(key_, instance_id_));
        case crypto_algorithm::CA_AES_CCM_256:
            return std::unique_ptr<aead_algorithm>(new aes_ccm<aes_key_length::AES_256>(key_, instance_id_));

        case crypto_algorithm::CA_INVALID:
        case crypto_algorithm::CA_NULL:
            return std::unique_ptr<aead_algorithm>();
    }
    return std::unique_ptr<aead_algorithm>();
}
*/
std::unique_ptr<mac_algorithm> session_parameters::get_mac_algorithm(byte_t domain_num_) const {
    VSOMEIP_WARNING << "session_parameters::get_mac_algorithm";
    if (domain_num_ == 10) {
        switch (get_crypto_algorithm()) {
            case crypto_algorithm::CA_CHACHA20_POLY1305_256:
                return std::unique_ptr<mac_algorithm>(new chacha20_poly1305(dk1_, instance_id_));

            case crypto_algorithm::CA_AES_GCM_128:
                return std::unique_ptr<mac_algorithm>(new aes_gcm<aes_key_length::AES_128>(dk1_, instance_id_));
            case crypto_algorithm::CA_AES_GCM_256:
                return std::unique_ptr<mac_algorithm>(new aes_gcm<aes_key_length::AES_256>(dk1_, instance_id_));

            case crypto_algorithm::CA_AES_CCM_128:
                return std::unique_ptr<mac_algorithm>(new aes_ccm<aes_key_length::AES_128>(dk1_, instance_id_));
            case crypto_algorithm::CA_AES_CCM_256:
                return std::unique_ptr<mac_algorithm>(new aes_ccm<aes_key_length::AES_256>(dk1_, instance_id_));

            case crypto_algorithm::CA_INVALID:
            case crypto_algorithm::CA_NULL:
                return std::unique_ptr<mac_algorithm>();
        }
    }
    else if (domain_num_ == 20) {
        switch (get_crypto_algorithm()) {
            case crypto_algorithm::CA_CHACHA20_POLY1305_256:
                return std::unique_ptr<mac_algorithm>(new chacha20_poly1305(dk2_, instance_id_));

            case crypto_algorithm::CA_AES_GCM_128:
                return std::unique_ptr<mac_algorithm>(new aes_gcm<aes_key_length::AES_128>(dk2_, instance_id_));
            case crypto_algorithm::CA_AES_GCM_256:
                return std::unique_ptr<mac_algorithm>(new aes_gcm<aes_key_length::AES_256>(dk2_, instance_id_));

            case crypto_algorithm::CA_AES_CCM_128:
                return std::unique_ptr<mac_algorithm>(new aes_ccm<aes_key_length::AES_128>(dk2_, instance_id_));
            case crypto_algorithm::CA_AES_CCM_256:
                return std::unique_ptr<mac_algorithm>(new aes_ccm<aes_key_length::AES_256>(dk2_, instance_id_));

            case crypto_algorithm::CA_INVALID:
            case crypto_algorithm::CA_NULL:
                return std::unique_ptr<mac_algorithm>();
        }
    }
    return std::unique_ptr<mac_algorithm>();
}

std::unique_ptr<mac_algorithm> session_parameters::get_deserializer_mac_algorithm() const {
    switch (get_crypto_algorithm()) {
        case crypto_algorithm::CA_CHACHA20_POLY1305_256:
            return std::unique_ptr<mac_algorithm>(new chacha20_poly1305(key_, instance_id_));

        case crypto_algorithm::CA_AES_GCM_128:
            return std::unique_ptr<mac_algorithm>(new aes_gcm<aes_key_length::AES_128>(key_, instance_id_));
        case crypto_algorithm::CA_AES_GCM_256:
            return std::unique_ptr<mac_algorithm>(new aes_gcm<aes_key_length::AES_256>(key_, instance_id_));

        case crypto_algorithm::CA_AES_CCM_128:
            return std::unique_ptr<mac_algorithm>(new aes_ccm<aes_key_length::AES_128>(key_, instance_id_));
        case crypto_algorithm::CA_AES_CCM_256:
            return std::unique_ptr<mac_algorithm>(new aes_ccm<aes_key_length::AES_256>(key_, instance_id_));

        case crypto_algorithm::CA_INVALID:
        case crypto_algorithm::CA_NULL:
            return std::unique_ptr<mac_algorithm>();
    }
    return std::unique_ptr<mac_algorithm>();
}

std::unique_ptr<mac_algorithm> session_parameters::get_uk_deserializer_mac_algorithm() const {
    switch (get_crypto_algorithm()) {
        case crypto_algorithm::CA_CHACHA20_POLY1305_256:
            return std::unique_ptr<mac_algorithm>(new chacha20_poly1305(uk_, instance_id_));

        case crypto_algorithm::CA_AES_GCM_128:
            return std::unique_ptr<mac_algorithm>(new aes_gcm<aes_key_length::AES_128>(uk_, instance_id_));
        case crypto_algorithm::CA_AES_GCM_256:
            return std::unique_ptr<mac_algorithm>(new aes_gcm<aes_key_length::AES_256>(uk_, instance_id_));

        case crypto_algorithm::CA_AES_CCM_128:
            return std::unique_ptr<mac_algorithm>(new aes_ccm<aes_key_length::AES_128>(uk_, instance_id_));
        case crypto_algorithm::CA_AES_CCM_256:
            return std::unique_ptr<mac_algorithm>(new aes_ccm<aes_key_length::AES_256>(uk_, instance_id_));

        case crypto_algorithm::CA_INVALID:
        case crypto_algorithm::CA_NULL:
            return std::unique_ptr<mac_algorithm>();
    }
    return std::unique_ptr<mac_algorithm>();
}


std::unique_ptr<aead_algorithm> session_parameters::get_aead_algorithm(byte_t domain_num_) const {
    VSOMEIP_WARNING << "session_parameters::get_aead_algorithm";
    if (domain_num_ == 10) {
        switch (get_crypto_algorithm()) {
            case crypto_algorithm::CA_CHACHA20_POLY1305_256:
                return std::unique_ptr<aead_algorithm>(new chacha20_poly1305(dk1_, instance_id_));

            case crypto_algorithm::CA_AES_GCM_128:
                return std::unique_ptr<aead_algorithm>(new aes_gcm<aes_key_length::AES_128>(dk1_, instance_id_));
            case crypto_algorithm::CA_AES_GCM_256:
                return std::unique_ptr<aead_algorithm>(new aes_gcm<aes_key_length::AES_256>(dk1_, instance_id_));

            case crypto_algorithm::CA_AES_CCM_128:
                return std::unique_ptr<aead_algorithm>(new aes_ccm<aes_key_length::AES_128>(dk1_, instance_id_));
            case crypto_algorithm::CA_AES_CCM_256:
                return std::unique_ptr<aead_algorithm>(new aes_ccm<aes_key_length::AES_256>(dk1_, instance_id_));

            case crypto_algorithm::CA_INVALID:
            case crypto_algorithm::CA_NULL:
                return std::unique_ptr<aead_algorithm>();
        }
    }
    else if (domain_num_ == 20) {
        switch (get_crypto_algorithm()) {
            case crypto_algorithm::CA_CHACHA20_POLY1305_256:
                return std::unique_ptr<aead_algorithm>(new chacha20_poly1305(dk2_, instance_id_));

            case crypto_algorithm::CA_AES_GCM_128:
                return std::unique_ptr<aead_algorithm>(new aes_gcm<aes_key_length::AES_128>(dk2_, instance_id_));
            case crypto_algorithm::CA_AES_GCM_256:
                return std::unique_ptr<aead_algorithm>(new aes_gcm<aes_key_length::AES_256>(dk2_, instance_id_));

            case crypto_algorithm::CA_AES_CCM_128:
                return std::unique_ptr<aead_algorithm>(new aes_ccm<aes_key_length::AES_128>(dk2_, instance_id_));
            case crypto_algorithm::CA_AES_CCM_256:
                return std::unique_ptr<aead_algorithm>(new aes_ccm<aes_key_length::AES_256>(dk2_, instance_id_));

            case crypto_algorithm::CA_INVALID:
            case crypto_algorithm::CA_NULL:
                return std::unique_ptr<aead_algorithm>();
        }
    }
    VSOMEIP_WARNING << "session_parameters::get_aead_algorithm not found";
    return std::unique_ptr<aead_algorithm>();
}

std::unique_ptr<aead_algorithm> session_parameters::get_deserializer_aead_algorithm() const {
    switch (get_crypto_algorithm()) {
        case crypto_algorithm::CA_CHACHA20_POLY1305_256:
            return std::unique_ptr<aead_algorithm>(new chacha20_poly1305(key_, instance_id_));

        case crypto_algorithm::CA_AES_GCM_128:
            return std::unique_ptr<aead_algorithm>(new aes_gcm<aes_key_length::AES_128>(key_, instance_id_));
        case crypto_algorithm::CA_AES_GCM_256:
            return std::unique_ptr<aead_algorithm>(new aes_gcm<aes_key_length::AES_256>(key_, instance_id_));

        case crypto_algorithm::CA_AES_CCM_128:
            return std::unique_ptr<aead_algorithm>(new aes_ccm<aes_key_length::AES_128>(key_, instance_id_));
        case crypto_algorithm::CA_AES_CCM_256:
            return std::unique_ptr<aead_algorithm>(new aes_ccm<aes_key_length::AES_256>(key_, instance_id_));

        case crypto_algorithm::CA_INVALID:
        case crypto_algorithm::CA_NULL:
            return std::unique_ptr<aead_algorithm>();
    }
    return std::unique_ptr<aead_algorithm>();
}

std::unique_ptr<aead_algorithm> session_parameters::get_uk_deserializer_aead_algorithm() const {
    switch (get_crypto_algorithm()) {
        case crypto_algorithm::CA_CHACHA20_POLY1305_256:
            return std::unique_ptr<aead_algorithm>(new chacha20_poly1305(uk_, instance_id_));

        case crypto_algorithm::CA_AES_GCM_128:
            return std::unique_ptr<aead_algorithm>(new aes_gcm<aes_key_length::AES_128>(uk_, instance_id_));
        case crypto_algorithm::CA_AES_GCM_256:
            return std::unique_ptr<aead_algorithm>(new aes_gcm<aes_key_length::AES_256>(uk_, instance_id_));

        case crypto_algorithm::CA_AES_CCM_128:
            return std::unique_ptr<aead_algorithm>(new aes_ccm<aes_key_length::AES_128>(uk_, instance_id_));
        case crypto_algorithm::CA_AES_CCM_256:
            return std::unique_ptr<aead_algorithm>(new aes_ccm<aes_key_length::AES_256>(uk_, instance_id_));

        case crypto_algorithm::CA_INVALID:
        case crypto_algorithm::CA_NULL:
            return std::unique_ptr<aead_algorithm>();
    }
    return std::unique_ptr<aead_algorithm>();
}
// ===============================




// =========================================
/*
bool session_parameters::initialize_serializers(uint32_t _buffer_shrink_threshold) {

    switch (get_security_level()) {
        case security_level::SL_NOSEC: {
            serializer_ = std::make_shared<message_serializer_nosec>(_buffer_shrink_threshold);
            deserializer_ = std::make_shared<message_deserializer_nosec>(_buffer_shrink_threshold);
            return true;
        }

        case security_level::SL_AUTHENTICATION: {
            auto serializer_algorithm = _algorithm();
            auto deserializer_algorithm = get_mac_algorithm();

            if (!serializer_algorithm || !deserializer_algorithm) {
                return false;
            }

            serializer_ = std::make_shared<message_serializer_authentication>(
                    _buffer_shrink_threshold, std::move(serializer_algorithm));
            deserializer_ = std::make_shared<message_deserializer_authentication>(
                    _buffer_shrink_threshold, std::move(deserializer_algorithm));
            return true;
        }

        case security_level::SL_CONFIDENTIALITY: {
            auto serializer_algorithm = get_aead_algorithm();
            auto deserializer_algorithm = get_aead_algorithm();

            if (!serializer_algorithm || !deserializer_algorithm) {
                return false;
            }

            serializer_ = std::make_shared<message_serializer_confidentiality>(
                    _buffer_shrink_threshold, std::move(serializer_algorithm));
            deserializer_ = std::make_shared<message_deserializer_confidentiality>(
                    _buffer_shrink_threshold, std::move(deserializer_algorithm));
            return true;
        }

        case security_level::SL_INVALID: {
            return false;
        }
    }

    return false;
}
*/
bool session_parameters::initialize_serializers(uint32_t _buffer_shrink_threshold) {
    VSOMEIP_WARNING << "session_parameters::initialize_serializers";

    switch (get_security_level()) {
        case security_level::SL_NOSEC: {
            serializer1_ = std::make_shared<message_serializer_nosec>(_buffer_shrink_threshold);
	        serializer2_ = std::make_shared<message_serializer_nosec>(_buffer_shrink_threshold);
            deserializer_ = std::make_shared<message_deserializer_nosec>(_buffer_shrink_threshold);
            uk_deserializer_ = std::make_shared<message_deserializer_nosec>(_buffer_shrink_threshold);
            return true;
        }

        case security_level::SL_AUTHENTICATION: {
            auto serializer_algorithm1 = get_mac_algorithm(10);
	        auto serializer_algorithm2 = get_mac_algorithm(20);
            auto deserializer_algorithm = get_deserializer_mac_algorithm();
            auto uk_deserializer_algorithm = get_uk_deserializer_mac_algorithm();

            if (!serializer_algorithm1 || !serializer_algorithm2 || !deserializer_algorithm) {
                return false;
            }

            serializer1_ = std::make_shared<message_serializer_authentication>(
                    _buffer_shrink_threshold, std::move(serializer_algorithm1));
            serializer2_ = std::make_shared<message_serializer_authentication>(
                    _buffer_shrink_threshold, std::move(serializer_algorithm2));
            deserializer_ = std::make_shared<message_deserializer_authentication>(
                    _buffer_shrink_threshold, std::move(deserializer_algorithm));

            uk_deserializer_ = std::make_shared<message_deserializer_authentication>(
                    _buffer_shrink_threshold, std::move(deserializer_algorithm));
            return true;
        }

        case security_level::SL_CONFIDENTIALITY: {
            auto serializer_algorithm1 = get_aead_algorithm(10);
            auto serializer_algorithm2 = get_aead_algorithm(20);
            auto deserializer_algorithm = get_deserializer_aead_algorithm();
            auto uk_deserializer_algorithm = get_uk_deserializer_aead_algorithm();

            if (!serializer_algorithm1 || !serializer_algorithm2 || !deserializer_algorithm) {
                return false;
            }

            serializer1_ = std::make_shared<message_serializer_confidentiality>(
                    _buffer_shrink_threshold, std::move(serializer_algorithm1));
            serializer2_ = std::make_shared<message_serializer_confidentiality>(
                    _buffer_shrink_threshold, std::move(serializer_algorithm2));
            deserializer_ = std::make_shared<message_deserializer_confidentiality>(
                    _buffer_shrink_threshold, std::move(deserializer_algorithm));

            uk_deserializer_ = std::make_shared<message_deserializer_confidentiality>(
                    _buffer_shrink_threshold, std::move(deserializer_algorithm));
            return true;
        }

        case security_level::SL_INVALID: {
            return false;
        }
    }

    return false;
}

// =========================================
} // namespace vsomeip

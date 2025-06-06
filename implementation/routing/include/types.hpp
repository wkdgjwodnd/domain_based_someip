// Copyright (C) 2014-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_ROUTING_TYPES_HPP
#define VSOMEIP_ROUTING_TYPES_HPP

#include <map>
#include <memory>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/steady_timer.hpp>

#include <vsomeip/primitive_types.hpp>
#include <vsomeip/constants.hpp>

#include "../../service_discovery/include/message_impl.hpp"
#include "../../configuration/include/internal.hpp"
#include "../../security/include/session_establishment.hpp"

#include "../../logging/include/logger.hpp"

namespace vsomeip {

class serviceinfo;
class endpoint_definition;
class session_parameters;

typedef std::map<service_t,
                 std::map<instance_t,
                          std::shared_ptr<serviceinfo> > > services_t;

typedef std::map<service_t,
        std::map<instance_t,
                std::shared_ptr<session_parameters> > > sessions_t;
                // session_t는 service, instance 두 개의 map으로 중첩된 구조를 가지고 있음.
                // map은 find를 통하여 찾을 수 있고,find(service)와 find(instance)를 통하여 session을 찾을 수 있음.

class eventgroupinfo;

typedef std::map<service_t,
                 std::map<instance_t,
                          std::map<eventgroup_t,
                                   std::shared_ptr<
                                       eventgroupinfo> > > > eventgroups_t;

enum class registration_type_e : std::uint8_t {
    REGISTER = 0x1,
    DEREGISTER = 0x2,
    DEREGISTER_ON_ERROR = 0x3
};

struct sd_message_identifier_t {
    sd_message_identifier_t(session_t _session,
                            boost::asio::ip::address _sender,
                            boost::asio::ip::address _destination,
                            const std::shared_ptr<sd::message_impl> &_response) :
            session_(_session),
            sender_(_sender),
            destination_(_destination),
            response_(_response) {
    }

    sd_message_identifier_t() :
        session_(0),
        sender_(boost::asio::ip::address()),
        destination_(boost::asio::ip::address()),
        response_(std::shared_ptr<sd::message_impl>()) {
    }

    bool operator==(const sd_message_identifier_t &_other) const {
        return !(session_ != _other.session_ ||
                sender_ != _other.sender_ ||
                destination_ != _other.destination_ ||
                response_ != _other.response_);
    }

    bool operator<(const sd_message_identifier_t &_other) const {
        return (session_ < _other.session_
                || (session_ == _other.session_ && sender_ < _other.sender_)
                || (session_ == _other.session_ && sender_ == _other.sender_
                        && destination_ < _other.destination_)
                || (session_ == _other.session_ && sender_ == _other.sender_
                        && destination_ == _other.destination_
                        && response_ < _other.response_));
    }

    session_t session_;
    boost::asio::ip::address sender_;
    boost::asio::ip::address destination_;
    std::shared_ptr<sd::message_impl> response_;
};

struct pending_subscription_t {
    pending_subscription_t(
            std::shared_ptr<sd_message_identifier_t> _sd_message_identifier,
            std::shared_ptr<endpoint_definition> _subscriber,
            std::shared_ptr<endpoint_definition> _target,
            ttl_t _ttl,
            client_t _subscribing_client) :
            sd_message_identifier_(_sd_message_identifier),
            subscriber_(_subscriber),
            target_(_target),
            ttl_(_ttl),
            subscribing_client_(_subscribing_client),
            pending_subscription_id_(DEFAULT_SUBSCRIPTION) {
    }
    pending_subscription_t () :
        sd_message_identifier_(std::shared_ptr<sd_message_identifier_t>()),
        subscriber_(std::shared_ptr<endpoint_definition>()),
        target_(std::shared_ptr<endpoint_definition>()),
        ttl_(0),
        subscribing_client_(VSOMEIP_ROUTING_CLIENT),
        pending_subscription_id_(DEFAULT_SUBSCRIPTION) {
    }
    std::shared_ptr<sd_message_identifier_t> sd_message_identifier_;
    std::shared_ptr<endpoint_definition> subscriber_;
    std::shared_ptr<endpoint_definition> target_;
    ttl_t ttl_;
    client_t subscribing_client_;
    pending_subscription_id_t pending_subscription_id_;
};

enum remote_subscription_state_e : std::uint8_t {
    SUBSCRIPTION_ACKED,
    SUBSCRIPTION_NACKED,
    SUBSCRIPTION_PENDING,
    SUBSCRIPTION_ERROR
};

struct pending_session_establishment_request_t {

    using challenge_t = session_establishment_message::challenge_t;

    pending_session_establishment_request_t(major_version_t _major_version, minor_version_t _minor_version,
                                            boost::asio::io_service &_io)
            : major_version_(_major_version), minor_version_(_minor_version),
              request_timer_(_io), establishment_completed_(false) {
    }

    void add_challenge(const challenge_t &_challenge) {
        challenges_.insert(_challenge);
    }

    bool is_valid_challenge(const challenge_t &_challenge) {
        return challenges_.find(_challenge) != challenges_.end();
    }

    mutable std::mutex mutex_;
    const major_version_t major_version_;
    const minor_version_t minor_version_;
    std::set<challenge_t> challenges_;
    boost::asio::steady_timer request_timer_;
    bool establishment_completed_;
};

typedef std::map<service_t, std::map<instance_t,
                std::shared_ptr<pending_session_establishment_request_t> > > pending_session_establishment_requests_t;

}
// namespace vsomeip

#endif // VSOMEIP_ROUTING_TYPES_HPP

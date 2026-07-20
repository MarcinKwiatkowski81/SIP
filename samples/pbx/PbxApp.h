// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

/**
 * @file PbxApp.h
 * @brief Sample PBX application wrapper around SipServer.
 */
#pragma once

#include "SipServer.h"
#include <atomic>
#include <string>
#include <vector>

namespace sample_pbx {

/** @brief Runtime configuration for sample PBX executable. */
struct PbxConfig {
    /** Local SIP bind address. */
    std::string bindAddr = "0.0.0.0";
    /** Local SIP listen port. */
    uint16_t sipPort = 5060;
    /** SIP realm/domain used for users and registration. */
    std::string domain = "pbx.local";
    /** Nonce secret used by digest auth. */
    std::string nonceSecret = "sample_pbx_nonce";

    /** Enable UDP SIP listener. */
    bool enableUdp = true;
    /** Enable TCP SIP listener. */
    bool enableTcp = true;

    /** Start of RTP port allocation range. */
    uint16_t rtpBasePort = 20000;
    /** Optional advertised media address for NAT scenarios. */
    std::string rtpAdvertiseAddr;

    /** Auto-provision extension start value. */
    int extStart = 100;
    /** Auto-provision extension end value (inclusive). */
    int extEnd = 199;
    /** Explicit users to seed in addition to extension range. */
    std::vector<std::string> explicitUsers;
    /** Codec plugin shared objects to load at startup. */
    std::vector<std::string> codecPlugins;
    /** Print registered codecs on startup. */
    bool printCodecs = false;

    /** Optional persistent user DB path. */
    std::string userDbPath;
    /** Optional CDR output file path. */
    std::string cdrPath;
};

/** @brief Sample PBX application lifecycle and policy hooks. */
class PbxApp {
public:
    /** @brief Initialize and start SIP server with PBX policy. */
    bool start(const PbxConfig& cfg);
    /** @brief Run interactive command loop. */
    void run();
    /** @brief Stop server and background activities. */
    void stop();

private:
    static std::string makePassword(const std::string& user);
    static bool validUsername(const std::string& user);
    static bool parseUserFromUri(const char* uri, std::string& outUser);

    bool seedUsers();

    PbxConfig cfg_;
    sip::SipServer server_;
    std::atomic<bool> running_{false};
};

} // namespace sample_pbx

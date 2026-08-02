// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

#include "PbxApp.h"

#include "Uri.h"
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <set>
#include <sys/select.h>
#include <unistd.h>

namespace sample_pbx {

namespace {
volatile std::sig_atomic_t gStop = 0;

void sigHandler(int) {
    gStop = 1;
}

} // namespace

std::string PbxApp::makePassword(const std::string& user) {
    return std::string("pass_") + user;
}

bool PbxApp::validUsername(const std::string& user) {
    if (user.empty() || user.size() > 63) return false;
    for (char c : user) {
        const bool ok = (c >= 'a' && c <= 'z') ||
                        (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') ||
                        c == '_' || c == '-' || c == '.';
        if (!ok) return false;
    }
    return true;
}

bool PbxApp::parseUserFromUri(const char* uri, std::string& outUser) {
    auto parsed = sip::SipUri::parse(uri ? uri : "");
    if (!parsed.ok() || parsed->user.empty()) return false;
    outUser.assign(parsed->user.c_str(), parsed->user.len);
    return true;
}

bool PbxApp::seedUsers() {
    std::set<std::string> users;

    if (cfg_.extStart <= cfg_.extEnd) {
        for (int ext = cfg_.extStart; ext <= cfg_.extEnd; ++ext) {
            users.insert(std::to_string(ext));
        }
    }

    for (const std::string& user : cfg_.explicitUsers) {
        users.insert(user);
    }

    size_t added = 0;
    for (const std::string& user : users) {
        if (!validUsername(user)) {
            std::fprintf(stderr, "[PBX] Skipping invalid username '%s'\n", user.c_str());
            continue;
        }
        const std::string pass = makePassword(user);
        if (!server_.addUser(user.c_str(), pass.c_str(), true, true, false)) {
            std::fprintf(stderr, "[PBX] Failed to add user '%s'\n", user.c_str());
            continue;
        }
        ++added;
    }

    std::printf("[PBX] Provisioned %zu endpoint credentials\n", added);
    if (added > 0) {
        std::printf("[PBX] Password policy: pass_ + username (example: 101 -> pass_101)\n");
    }
    return added > 0;
}

bool PbxApp::start(const PbxConfig& cfg) {
    cfg_ = cfg;
    gStop = 0;

    sip::ServerConfig serverCfg;
    serverCfg.localAddr.assign(cfg_.bindAddr.c_str(), cfg_.bindAddr.size());
    serverCfg.port = cfg_.sipPort;
    serverCfg.enableUdp = cfg_.enableUdp;
    serverCfg.enableTcp = cfg_.enableTcp;
    serverCfg.domain.assign(cfg_.domain.c_str(), cfg_.domain.size());
    serverCfg.realm.assign(cfg_.domain.c_str(), cfg_.domain.size());
    serverCfg.nonceSecret.assign(cfg_.nonceSecret.c_str(), cfg_.nonceSecret.size());

    serverCfg.requireRegAuth = true;
    serverCfg.requireCallAuth = false;
    serverCfg.b2buaMode = true;

    serverCfg.rtpBasePort = cfg_.rtpBasePort;
    if (!cfg_.rtpAdvertiseAddr.empty()) {
        // Explicit -r <ip> from command line — always use it.
        serverCfg.rtpLocalAddr.assign(cfg_.rtpAdvertiseAddr.c_str(),
                                      cfg_.rtpAdvertiseAddr.size());
    } else if (cfg_.bindAddr != "0.0.0.0" && !cfg_.bindAddr.empty()) {
        // Bound to a specific address — use it for RTP as well.
        serverCfg.rtpLocalAddr.assign(cfg_.bindAddr.c_str(), cfg_.bindAddr.size());
    }
    // Otherwise leave rtpLocalAddr empty so SipServer::init() auto-detects
    // the primary NIC address via getifaddrs() at startup.

    if (!cfg_.userDbPath.empty()) {
        serverCfg.userDbPath.assign(cfg_.userDbPath.c_str(), cfg_.userDbPath.size());
    }
    if (!cfg_.cdrPath.empty()) {
        serverCfg.cdrPath.assign(cfg_.cdrPath.c_str(), cfg_.cdrPath.size());
    }

    if (!cfg_.codecPlugins.empty()) {
        size_t copied = 0;
        for (const std::string& soPath : cfg_.codecPlugins) {
            if (soPath.empty()) continue;
            if (copied >= sip::ServerConfig::MaxCodecPlugins) {
                std::fprintf(stderr, "[PBX] Codec plugin limit reached (%zu)\n",
                             sip::ServerConfig::MaxCodecPlugins);
                break;
            }
            serverCfg.codecPluginPaths[copied].assign(soPath.c_str(), soPath.size());
            ++copied;
        }
        serverCfg.codecPluginCount = copied;
    }

    sip::ServerCallbacks cbs;
    cbs.onRegister = [](const char* aor, const char* contact, bool reg) {
        std::printf("[PBX] %s %s via %s\n", reg ? "REGISTER" : "UNREGISTER", aor, contact);
    };
    cbs.onCallAttempt = [this](const char* from, const char* to) {
        std::string fromUser;
        std::string toUser;

        const bool fromOk = parseUserFromUri(from, fromUser);
        const bool toOk = parseUserFromUri(to, toUser);
        if (!fromOk || !toOk) {
            std::fprintf(stderr, "[PBX] Rejecting malformed INVITE: from=%s to=%s\n", from, to);
            return false;
        }

        const sip::UserEntry* caller = server_.userDb().find(fromUser.c_str());
        if (!caller || !caller->enabled || !caller->canCall) {
            std::fprintf(stderr, "[PBX] Rejecting call from '%s': caller not allowed\n", fromUser.c_str());
            return false;
        }

        std::printf("[PBX] Call attempt %s -> %s\n", fromUser.c_str(), toUser.c_str());
        return true;
    };
    cbs.onCallEnd = [](const sip::CdrRecord& cdr) {
        std::printf("[PBX] Call end %s -> %s code=%d durationMs=%lld\n",
            cdr.fromUri.c_str(),
            cdr.toUri.c_str(),
            cdr.sipCode,
            (long long)(cdr.endMs - cdr.startMs));
    };

    if (!server_.init(serverCfg, cbs)) {
        std::fprintf(stderr, "[PBX] Failed to initialize SIP server\n");
        return false;
    }

    if (!seedUsers()) {
        std::fprintf(stderr, "[PBX] No users were provisioned; refusing to run\n");
        server_.shutdown();
        return false;
    }

    std::signal(SIGINT, sigHandler);
    std::signal(SIGTERM, sigHandler);

    running_ = true;
    return true;
}

void PbxApp::run() {
    if (!running_) return;

    std::printf("\n[PBX] Ready on %s:%u  domain=%s\n",
        cfg_.bindAddr.c_str(), cfg_.sipPort, cfg_.domain.c_str());
    std::printf("[PBX] B2BUA media anchor enabled (RTP relay + basic codec transcoding)\n");
    std::printf("[PBX] Commands: r=registrations c=calls s=stats k=codecs u=users q=quit\n\n");

    if (cfg_.printCodecs) {
        server_.printCodecs();
    }

    while (running_ && !gStop) {
        server_.tick();

        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        timeval tv{0, 50 * 1000};
        if (select(STDIN_FILENO + 1, &fds, nullptr, nullptr, &tv) > 0) {
            char line[128] = {};
            if (!std::fgets(line, sizeof(line), stdin)) break;
            switch (line[0]) {
            case 'r':
                server_.printRegistrations();
                break;
            case 'c':
                server_.printCalls();
                break;
            case 's':
                server_.printStats();
                break;
            case 'k':
                server_.printCodecs();
                break;
            case 'u':
                server_.userDb().printAll();
                break;
            case 'q':
                running_ = false;
                break;
            default:
                break;
            }
        }
    }

    stop();
}

void PbxApp::stop() {
    running_ = false;
    server_.shutdown();
}

} // namespace sample_pbx

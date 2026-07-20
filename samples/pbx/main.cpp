// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

#include "PbxApp.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <getopt.h>

namespace {

void printUsage(const char* prog) {
    std::printf(
        "Usage: %s [options]\n"
        "  -l <bind-ip>         SIP bind address (default: 0.0.0.0)\n"
        "  -p <port>            SIP listen port (default: 5060)\n"
        "  -d <domain>          SIP domain/realm (default: pbx.local)\n"
        "  -r <rtp-ip>          RTP address advertised in SDP (default: bind-ip)\n"
        "  -b <rtp-base-port>   RTP base UDP port (default: 20000)\n"
        "  -x <start-end>       Provision extension range (default: 100-199)\n"
        "  -e <username>        Provision one extra endpoint (repeatable)\n"
        "  -g <codec.so>        Load codec plugin .so (repeatable)\n"
        "  --print-codecs       Print active codec registry on startup\n"
        "  -u <users.db>        Persist user DB to file\n"
        "  -c <cdr.csv>         Write CDR CSV to file\n"
        "  --no-udp             Disable UDP transport\n"
        "  --no-tcp             Disable TCP transport\n"
        "\n"
        "Auth policy: username is callable extension, password is pass_ + username.\n",
        prog);
}

bool parseRange(const char* s, int& outStart, int& outEnd) {
    if (!s) return false;
    int a = 0;
    int b = 0;
    if (std::sscanf(s, "%d-%d", &a, &b) != 2) return false;
    if (a <= 0 || b <= 0 || a > b) return false;
    outStart = a;
    outEnd = b;
    return true;
}

} // namespace

int main(int argc, char** argv) {
    sample_pbx::PbxConfig cfg;

    static option longOpts[] = {
        {"no-udp", no_argument, nullptr, 1001},
        {"no-tcp", no_argument, nullptr, 1002},
        {"print-codecs", no_argument, nullptr, 1003},
        {nullptr, 0, nullptr, 0}
    };

    int opt = 0;
    int longIdx = 0;
    while ((opt = getopt_long(argc, argv, "l:p:d:r:b:x:e:g:u:c:h", longOpts, &longIdx)) != -1) {
        switch (opt) {
        case 'l':
            cfg.bindAddr = optarg;
            break;
        case 'p':
            cfg.sipPort = static_cast<uint16_t>(std::atoi(optarg));
            break;
        case 'd':
            cfg.domain = optarg;
            break;
        case 'r':
            cfg.rtpAdvertiseAddr = optarg;
            break;
        case 'b':
            cfg.rtpBasePort = static_cast<uint16_t>(std::atoi(optarg));
            break;
        case 'x':
            if (!parseRange(optarg, cfg.extStart, cfg.extEnd)) {
                std::fprintf(stderr, "Invalid extension range: %s\n", optarg);
                return 1;
            }
            break;
        case 'e':
            cfg.explicitUsers.emplace_back(optarg);
            break;
        case 'g':
            cfg.codecPlugins.emplace_back(optarg);
            break;
        case 'u':
            cfg.userDbPath = optarg;
            break;
        case 'c':
            cfg.cdrPath = optarg;
            break;
        case 1001:
            cfg.enableUdp = false;
            break;
        case 1002:
            cfg.enableTcp = false;
            break;
        case 1003:
            cfg.printCodecs = true;
            break;
        case 'h':
            printUsage(argv[0]);
            return 0;
        default:
            printUsage(argv[0]);
            return 1;
        }
    }

    if (!cfg.enableUdp && !cfg.enableTcp) {
        std::fprintf(stderr, "At least one transport must be enabled\n");
        return 1;
    }

    sample_pbx::PbxApp app;
    if (!app.start(cfg)) {
        return 1;
    }
    app.run();
    return 0;
}

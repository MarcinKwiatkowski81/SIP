// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

// sip_server_main.cpp – Standalone SIP server executable
//
// Usage:
//   sip_server [options]
//     -d <domain>        SIP domain  (default: localhost)
//     -l <addr>          Bind address (default: 0.0.0.0)
//     -p <port>          SIP port     (default: 5060)
//     -b                 B2BUA mode   (default: proxy mode)
//     -A                 Require auth for REGISTER
//     -u users.txt       User database file
//     -c cdr.csv         CDR output file
//     -a <user:pass>     Add user (can repeat)
//     --no-tcp           Disable TCP transport
//     --no-udp           Disable UDP transport
//
// Admin REPL (interactive):
//   r  – show registrations
//   c  – show active calls
//   s  – stats
//   u  – show users
//   q  – quit
#include "SipServer.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <pthread.h>
#include <sys/time.h>

using namespace sip;

static volatile bool g_quit = false;
static void sigHandler(int) { g_quit=true; }

int main(int argc, char** argv) {
    ServerConfig cfg;
    cfg.domain.assign("localhost",9);
    cfg.realm.assign("localhost",9);
    cfg.nonceSecret.assign("sip_server_secret",17);
    cfg.requireRegAuth = false;  // disabled by default for easy setup
    cfg.b2buaMode      = false;

    bool noTcp=false, noUdp=false;

    int opt;
    while ((opt=getopt(argc,argv,"d:l:p:bAu:c:a:h")) != -1) {
        switch(opt) {
        case 'd':
            cfg.domain.assign(optarg,strlen(optarg));
            cfg.realm.assign(optarg,strlen(optarg));
            break;
        case 'l': cfg.localAddr.assign(optarg,strlen(optarg)); break;
        case 'p': cfg.port=(uint16_t)atoi(optarg); break;
        case 'b': cfg.b2buaMode=true; break;
        case 'A': cfg.requireRegAuth=true; break;
        case 'u': cfg.userDbPath.assign(optarg,strlen(optarg)); break;
        case 'c': cfg.cdrPath.assign(optarg,strlen(optarg)); break;
        case 'a': /* handled below */ break;
        case 'h':
        default:
            printf("Usage: %s [-d domain] [-l addr] [-p port] [-b] [-A]\n"
                   "       [-u users.txt] [-c cdr.csv] [-a user:pass] ...\n"
                   "  -b  B2BUA mode (default: stateful proxy)\n"
                   "  -A  Require Digest auth for REGISTER\n", argv[0]);
            return opt=='h'?0:1;
        }
    }

    // Set RTP relay address = bind address
    if (!cfg.localAddr.empty()) cfg.rtpLocalAddr = cfg.localAddr;
    cfg.enableTcp = !noTcp;
    cfg.enableUdp = !noUdp;

    signal(SIGINT,  sigHandler);
    signal(SIGTERM, sigHandler);
    signal(SIGPIPE, SIG_IGN);

    ServerCallbacks cbs;
    cbs.onRegister=[](const char* aor, const char* contact, bool reg){
        printf("[EVENT] %s  %s  %s\n", reg?"REGISTERED":"UNREGISTERED", aor, contact);
    };
    cbs.onCallEnd=[](const CdrRecord& cdr){
        printf("[CDR]   %s → %s  %lldms  %s\n",
               cdr.fromUri.c_str(), cdr.toUri.c_str(),
               (long long)(cdr.endMs-cdr.startMs),
               cdr.result==CdrResult::Answered?"ANSWERED":"NOT_ANSWERED");
    };

    SipServer server;
    if (!server.init(cfg, cbs)) {
        fputs("[ERROR] Failed to start server\n", stderr); return 1;
    }

    // Add users from -a flags
    optind=1;
    while ((opt=getopt(argc,argv,"d:l:p:bAu:c:a:h"))!=-1) {
        if (opt=='a') {
            char user[64]={}, pass[64]={};
            if (sscanf(optarg,"%63[^:]:%63s",user,pass)==2) {
                server.addUser(user,pass);
                printf("[USER]  Added user '%s'\n",user);
            }
        }
    }

    // Tick thread
    pthread_t tickTid;
    auto tickFn=[](void* arg)->void*{
        auto* s=(SipServer*)arg;
        while(!g_quit){
            struct timespec ts{0,50000000L}; nanosleep(&ts,nullptr);
            s->tick();
        }
        return nullptr;
    };
    pthread_create(&tickTid,nullptr,+tickFn,&server);

    printf("\nSIP Server ready.  Commands: r=registrations c=calls s=stats u=users q=quit\n\n");

    // Interactive admin REPL
    char line[256];
    while (!g_quit) {
        printf("sip> "); fflush(stdout);
        // Non-blocking readline with 200ms check
        fd_set fds; FD_ZERO(&fds); FD_SET(STDIN_FILENO,&fds);
        struct timeval tv{0,200000};
        if (select(STDIN_FILENO+1,&fds,nullptr,nullptr,&tv)>0) {
            if (!fgets(line,sizeof line,stdin)) break;
            char cmd=line[0];
            switch(cmd) {
            case 'r': server.printRegistrations(); break;
            case 'c': server.printCalls();         break;
            case 's': server.printStats();         break;
            case 'u': server.userDb().printAll();  break;
            case 'q': g_quit=true;                 break;
            case 'h': case '?':
                printf("  r  registrations\n  c  active calls\n"
                       "  s  stats\n  u  users\n  q  quit\n"); break;
            default: break;
            }
        }
    }

    g_quit=true;
    pthread_join(tickTid,nullptr);
    server.shutdown();
    printf("\nServer stopped.\n");
    return 0;
}

// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

// main.cpp – Interactive SIP client REPL
// Usage: sip_client -u user -d domain -r registrar [-p password] [-l addr]
#include "SipStack.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <pthread.h>
#include <sys/time.h>

using namespace sip;

static volatile bool quit=false;
static SipStack*     gStack=nullptr;
static CallHandle    gCall=InvalidDialog;

static void sigHandler(int) { quit=true; if(gStack) gStack->shutdown(); }

static void printHelp() {
    printf("Commands:\n"
           "  r <expires>     REGISTER (default 3600)\n"
           "  u               Un-REGISTER (expires=0)\n"
           "  c <sip:user@host> INVITE\n"
           "  a               Accept incoming call\n"
           "  b               BYE current call\n"
           "  x               Cancel pending INVITE\n"
           "  h               Hold\n"
           "  R               Resume\n"
           "  d <digit>       Send DTMF (0-9,*,#,A-D)\n"
           "  m <target> <text> Send MESSAGE\n"
           "  o <target>      Send OPTIONS\n"
           "  s               Show call stats\n"
           "  q               Quit\n"
           "  ?               This help\n");
}

static uint8_t dtmfDigit(char c) {
    if(c>='0'&&c<='9') return (uint8_t)(c-'0');
    if(c=='*') return 10; if(c=='#') return 11;
    if(c>='A'&&c<='D') return (uint8_t)(c-'A'+12);
    if(c>='a'&&c<='d') return (uint8_t)(c-'a'+12);
    return 0xFF;
}

// Tick thread
static void* tickThread(void* arg) {
    SipStack* stack=(SipStack*)arg;
    while(!quit) {
        struct timespec ts={0,50*1000*1000L}; nanosleep(&ts,nullptr);
        stack->tick();
    }
    return nullptr;
}

int main(int argc, char** argv) {
    StackConfig cfg;
    cfg.localAddr.assign("0.0.0.0",7);
    cfg.localPort=SIP_UDP_PORT;
    cfg.regExpires=3600;

    int opt;
    while((opt=getopt(argc,argv,"u:d:r:p:l:P:h"))!=-1) {
        switch(opt) {
        case 'u': cfg.localUser.assign(optarg,strlen(optarg)); cfg.authUser=cfg.localUser; break;
        case 'd': cfg.localDomain.assign(optarg,strlen(optarg)); break;
        case 'r': cfg.registrarHost.assign(optarg,strlen(optarg)); break;
        case 'p': cfg.authPass.assign(optarg,strlen(optarg)); break;
        case 'l': cfg.localAddr.assign(optarg,strlen(optarg)); cfg.rtpLocalAddr=cfg.localAddr; break;
        case 'P': cfg.localPort=(uint16_t)atoi(optarg); break;
        case 'h': default:
            printf("Usage: %s -u user -d domain -r registrar [-p pass] [-l localIP] [-P localPort]\n",argv[0]);
            return 0;
        }
    }
    if(cfg.localUser.empty()||cfg.registrarHost.empty()) {
        fprintf(stderr,"Required: -u user, -r registrar\n"); return 1;
    }
    if(cfg.localDomain.empty()) cfg.localDomain=cfg.registrarHost;
    if(cfg.registrarPort==0)    cfg.registrarPort=SIP_UDP_PORT;

    CodecRegistry codecs;
    StackCallbacks cbs;
    cbs.onRegistered=[](bool ok,int c){ printf("[REG] %s (%d)\n",ok?"OK":"FAIL",c); };
    cbs.onInvite=[](CallHandle h,const SipMessage& m){ printf("[INVITE] from %s  handle=%u\n  type 'a' to accept, 'b' to reject\n",m.from.uri.c_str(),(unsigned)h); gCall=h; };
    cbs.onConnected=[](CallHandle h,RtpSession* r){ printf("[CONNECTED] call=%u  rtp=%s\n",(unsigned)h,r?"up":"no media"); gCall=h; };
    cbs.onBye=[](CallHandle h,int c){ printf("[BYE] call=%u code=%d\n",(unsigned)h,c); if(gCall==h) gCall=InvalidDialog; };
    cbs.onMessage=[](const char* from,const char* body,size_t len,const char*){ printf("[MSG] from %s: %.*s\n",from,(int)len,body); };
    cbs.onOptions=[](bool ok,int c){ printf("[OPTIONS] %s (%d)\n",ok?"OK":"FAIL",c); };

    SipStack stack;
    gStack=&stack;
    if(!stack.init(cfg,cbs,&codecs)) { fprintf(stderr,"Stack init failed\n"); return 1; }

    signal(SIGINT,sigHandler); signal(SIGTERM,sigHandler);

    pthread_t tickTid; pthread_create(&tickTid,nullptr,tickThread,&stack);

    printf("SIP client ready. Type '?' for help.\n");
    char line[256];
    while(!quit && fgets(line,sizeof line,stdin)) {
        // Strip newline
        size_t ll=strlen(line); while(ll&&(line[ll-1]=='\n'||line[ll-1]=='\r')) line[--ll]=0;
        if(!ll) continue;
        char cmd=line[0];
        const char* arg=ll>1?line+2:nullptr;
        switch(cmd) {
        case 'r': stack.doRegister(arg?(uint32_t)atoi(arg):3600); break;
        case 'u': stack.doRegister(0); break;
        case 'c':
            if(!arg) { puts("Usage: c <sip:user@host>"); break; }
            gCall=stack.call(arg);
            printf("[CALLING] handle=%u\n",(unsigned)gCall); break;
        case 'a':
            if(gCall==InvalidDialog) { puts("No pending call"); break; }
            stack.accept(gCall); break;
        case 'b':
            if(gCall==InvalidDialog) { puts("No active call"); break; }
            stack.bye(gCall); gCall=InvalidDialog; break;
        case 'x':
            if(gCall==InvalidDialog) { puts("No active call"); break; }
            stack.cancel(gCall); gCall=InvalidDialog; break;
        case 'h':
            if(gCall==InvalidDialog) { puts("No active call"); break; }
            stack.hold(gCall); puts("[HOLD]"); break;
        case 'R':
            if(gCall==InvalidDialog) { puts("No active call"); break; }
            stack.resume(gCall); puts("[RESUME]"); break;
        case 'd':
            if(!arg||gCall==InvalidDialog) { puts("Usage: d <digit>  (active call required)"); break; }
            { uint8_t dg=dtmfDigit(arg[0]); if(dg==0xFF){puts("Invalid digit");break;} stack.sendDtmf(gCall,dg); printf("[DTMF] %c\n",arg[0]); }
            break;
        case 'm': {
            if(!arg) { puts("Usage: m <target> <text>"); break; }
            char tgt[128],txt[128]; if(sscanf(arg,"%127s %127[^\n]",tgt,txt)==2) stack.sendMessage(tgt,txt,strlen(txt));
            break; }
        case 'o':
            if(!arg) { puts("Usage: o <target>"); break; }
            stack.options(arg); break;
        case 's': {
            RtpSession* r=stack.rtpOf(gCall);
            if(!r){ puts("No RTP"); break; }
            auto st=r->stats(); printf("[STATS] tx=%llu/%llu rx=%llu/%llu lost=%u jitter=%.1fms\n",
                (unsigned long long)st.txPkts,(unsigned long long)st.txBytes,
                (unsigned long long)st.rxPkts,(unsigned long long)st.rxBytes,
                st.rxLost,st.jitterMs); break; }
        case 'q': quit=true; break;
        case '?': printHelp(); break;
        default: printf("Unknown command '%c'. Type '?' for help.\n",cmd); break;
        }
    }

    quit=true; pthread_join(tickTid,nullptr); stack.shutdown();
    puts("Bye.");
    return 0;
}

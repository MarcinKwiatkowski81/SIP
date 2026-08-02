// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

// SipServer.cpp – SIP Server: Registrar + Stateful Proxy + B2BUA
#include "SipServer.h"
#include "Sdp.h"
#include "Rtp.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <sys/time.h>
#include <pthread.h>
#include <cerrno>
#include <algorithm>

namespace sip {

namespace {

ICodec* codecForPtFallback(uint8_t pt) {
    static G711u g711u;
    static G711a g711a;
    if (pt == 0) return &g711u;
    if (pt == 8) return &g711a;
    return nullptr;
}

ICodec* resolveCodec(CodecRegistry& reg, uint8_t pt, const char* name) {
    if (name && *name) {
        ICodec* byName = reg.findByName(name);
        if (byName) return byName;
    }
    ICodec* byPt = reg.findByPT(pt);
    if (byPt) return byPt;
    return codecForPtFallback(pt);
}

bool transcodeRtpPacket(const uint8_t* in, size_t inLen,
                        uint8_t* out, size_t outCap, size_t* outLen,
                        uint8_t dstPt, ICodec* srcCodec, ICodec* dstCodec) {
    if (!in || !out || !outLen || inLen < sizeof(RtpHdr) || outCap < inLen) {
        return false;
    }

    const RtpHdr* h = (const RtpHdr*)in;
    const size_t csrcBytes = (size_t)h->csrcCount() * 4U;
    const size_t hdrLen = sizeof(RtpHdr) + csrcBytes;
    if (h->version() != 2 || hdrLen > inLen || hdrLen > outCap) {
        return false;
    }

    const uint8_t inPt = h->pt();
    const uint8_t* payload = in + hdrLen;
    const size_t payLen = inLen - hdrLen;

    if (inPt == 101 || !srcCodec || !dstCodec) {
        memcpy(out, in, inLen);
        out[1] = (uint8_t)((out[1] & 0x80) | (dstPt & 0x7F));
        *outLen = inLen;
        return true;
    }

    if (srcCodec == dstCodec) {
        memcpy(out, in, inLen);
        out[1] = (uint8_t)((out[1] & 0x80) | (dstPt & 0x7F));
        *outLen = inLen;
        return true;
    }

    int16_t pcm[2048];
    const size_t samples = srcCodec->decode(payload, payLen, pcm, sizeof(pcm) / sizeof(pcm[0]));
    if (!samples) return false;

    uint8_t enc[2048];
    const size_t encLen = dstCodec->encode(pcm, samples, enc, sizeof(enc));
    if (!encLen || hdrLen + encLen > outCap) return false;

    memcpy(out, in, hdrLen);
    out[1] = (uint8_t)((out[1] & 0x80) | (dstPt & 0x7F));
    memcpy(out + hdrLen, enc, encLen);
    *outLen = hdrLen + encLen;
    return true;
}

} // namespace

// ── Helpers ───────────────────────────────────────────────────────────────────
int64_t SipServer::nowMs() {
    struct timeval tv; gettimeofday(&tv,nullptr);
    return (int64_t)tv.tv_sec*1000 + tv.tv_usec/1000;
}
uint32_t SipServer::rnd32() { return (uint32_t)rand()^(uint32_t)(rand()<<16); }

void SipServer::genBranch(Branch& b) const {
    char tmp[80]; snprintf(tmp,sizeof tmp,"z9hG4bK%08x%08x",rnd32(),rnd32());
    b.assign(tmp,strlen(tmp));
}
void SipServer::genCallId(CallId& id) const {
    // Use the routable IP so Call-IDs are globally unique and look well-formed.
    const char* ip = cfg_.rtpLocalAddr.empty()
                   ? cfg_.localAddr.c_str() : cfg_.rtpLocalAddr.c_str();
    char tmp[80]; snprintf(tmp,sizeof tmp,"%08x%08x@%s",rnd32(),rnd32(),ip);
    id.assign(tmp,strlen(tmp));
}
void SipServer::genTag(Tag& t) const {
    char tmp[16]; snprintf(tmp,sizeof tmp,"%08x",rnd32()); t.assign(tmp,8);
}
bool SipServer::isLocal(const char* domain) const {
    if (!domain || !*domain) return false;
    if (cfg_.domain   == domain) return true;
    if (cfg_.localAddr== domain) return true;
    if (strcmp(domain,"localhost")==0 || strcmp(domain,"127.0.0.1")==0) return true;

    // When the server is bound to 0.0.0.0 (all interfaces), phones reach us by
    // our actual NIC IP (e.g. 192.168.32.2) rather than the SIP domain name
    // (e.g. pbx.local).  Walk every local interface address so any such IP is
    // recognised as ours — without hard-coding it in the config.
    struct ifaddrs* ifa_list = nullptr;
    if (getifaddrs(&ifa_list) != 0) return false;
    bool found = false;
    for (struct ifaddrs* ifa = ifa_list; ifa && !found; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        char buf[INET_ADDRSTRLEN] = {};
        const auto* sa4 = reinterpret_cast<const sockaddr_in*>(ifa->ifa_addr);
        if (inet_ntop(AF_INET, &sa4->sin_addr, buf, sizeof buf))
            found = (strcmp(buf, domain) == 0);
    }
    freeifaddrs(ifa_list);
    return found;
}

// ── init ──────────────────────────────────────────────────────────────────────
bool SipServer::init(ServerConfig cfg, ServerCallbacks cbs) {
    cfg_ = cfg; cbs_ = cbs;
    srand((unsigned)time(nullptr)^(unsigned)getpid());
    memset(proxyCalls_,  0, sizeof proxyCalls_);
    memset(b2buaCalls_,  0, sizeof b2buaCalls_);
    memset(nonceCache_,  0, sizeof nonceCache_);
    nextRtpPort_ = cfg_.rtpBasePort;
    if (nextRtpPort_==0) nextRtpPort_=20000;

    // Load user DB
    if (!cfg_.userDbPath.empty()) {
        int n = users_.load(cfg_.userDbPath.c_str());
        if (n >= 0) printf("[SERVER] Loaded %d users from %s\n", n, cfg_.userDbPath.c_str());
    }

    // Open CDR
    if (!cfg_.cdrPath.empty()) cdr_.open(cfg_.cdrPath.c_str());

    // Register built-in codecs suitable for transcoding (without stubs).
    registerAllCodecs(codecs_, false);

    // Optional codec plugin loading for transcoding.
    for (size_t i = 0; i < cfg_.codecPluginCount && i < ServerConfig::MaxCodecPlugins; ++i) {
        const char* soPath = cfg_.codecPluginPaths[i].c_str();
        if (!soPath || !*soPath) continue;
        CodecPlugin p = CodecPlugin::fromSo(soPath);
        if (!p) {
            printf("[CODEC] Failed to load plugin: %s\n", soPath);
            continue;
        }
        ICodec* c = p.release();
        if (!codecs_.add(c)) {
            printf("[CODEC] Plugin rejected (duplicate/full): %s\n", soPath);
            delete c;
            continue;
        }
        printf("[CODEC] Plugin loaded: %s\n", soPath);
    }

    // Open transport
    Transport::Config tc;
    tc.localAddr  = cfg_.localAddr.empty() ? nullptr : cfg_.localAddr.c_str();
    tc.port       = cfg_.port;
    tc.enableUdp  = cfg_.enableUdp;
    tc.enableTcp  = cfg_.enableTcp;

    if (!transport_.open(tc, [this](const char* d,size_t l,
                                     const char* h,uint16_t p,bool tcp){
            Guard g(mu_); onRecv(d,l,h,p,tcp);
        })) return false;

    // Wire transaction layer — TCP-aware send
    txn_.init(
        [this](const char* h,uint16_t p,const char* d,size_t l)->bool{
            return transport_.sendUdp(d,l,h,p);
        },
        { [this](TxnId id,const SipMessage& m){ onTxnResponse(id,m); },
          [this](TxnId id,const SipMessage& m){ onTxnRequest(id,m); },
          [this](TxnId id){ onTxnTerminated(id); } }
    );

    // ── Auto-detect RTP advertise address ────────────────────────────────────
    // When the server is bound to 0.0.0.0 (all interfaces) and no explicit
    // -r <rtp-ip> was given, phones would receive SDP with c=IN IP4 0.0.0.0
    // which is unroutable.  Walk local interfaces to find the first non-loopback
    // IPv4 address and use it as the relay address advertised in SDP.
    if (cfg_.rtpLocalAddr.empty() &&
        (cfg_.localAddr.empty() || cfg_.localAddr == "0.0.0.0")) {
        struct ifaddrs* ifa_list = nullptr;
        if (getifaddrs(&ifa_list) == 0) {
            for (struct ifaddrs* ifa = ifa_list; ifa; ifa = ifa->ifa_next) {
                if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
                const auto* sa4 =
                    reinterpret_cast<const sockaddr_in*>(ifa->ifa_addr);
                if (sa4->sin_addr.s_addr == htonl(INADDR_LOOPBACK)) continue;
                char buf[INET_ADDRSTRLEN] = {};
                if (inet_ntop(AF_INET, &sa4->sin_addr, buf, sizeof buf)) {
                    cfg_.rtpLocalAddr.assign(buf, strlen(buf));
                    printf("[SERVER] RTP relay address auto-detected: %s\n", buf);
                    break;
                }
            }
            freeifaddrs(ifa_list);
        }
    }

    running_ = true;
    printf("[SERVER] SIP server started  %s:%u  domain=%s  mode=%s\n",
           tc.localAddr?tc.localAddr:"*", cfg_.port, cfg_.domain.c_str(),
           cfg_.b2buaMode?"B2BUA":"Proxy");
    return true;
}

// ── shutdown ──────────────────────────────────────────────────────────────────
void SipServer::shutdown() {
    running_ = false;
    transport_.close();
    cdr_.close();
    if (!cfg_.userDbPath.empty()) users_.save(cfg_.userDbPath.c_str());
    // Close B2BUA RTP relays
    for (auto& c : b2buaCalls_) { if (c.used) closeRtpRelay(c); }
}

// ── tick ──────────────────────────────────────────────────────────────────────
void SipServer::tick() {
    Guard g(mu_);
    int64_t now = nowMs();
    txn_.tick(now);
    reg_.expire(now);
}

// ── User management ───────────────────────────────────────────────────────────
bool SipServer::addUser(const char* u, const char* p,
                        bool canReg, bool canCall, bool isAdmin) {
    return users_.add(u, p, cfg_.realm.c_str(), canReg, canCall, isAdmin);
}
bool SipServer::removeUser(const char* u) { return users_.remove(u); }

// ── Transport receive → dispatch ─────────────────────────────────────────────
void SipServer::onRecv(const char* data, size_t len,
                       const char* srcHost, uint16_t srcPort, bool isTcp) {
    auto r = SipMessage::parse(data, len); if (!r.ok()) return;
    const SipMessage& msg = *r;
    Proto proto = isTcp ? Proto::Tcp : Proto::Udp; (void)proto;

    // Feed transaction layer first
    if (txn_.onMessage(msg, srcHost, srcPort)) return;

    // ACK for 2xx is outside transactions
    if (msg.isRequest && msg.method == Method::ACK) { handleAck(msg); return; }
}

// ── Transaction callbacks ─────────────────────────────────────────────────────
void SipServer::onTxnRequest(TxnId id, const SipMessage& msg) {
    Proto proto = Proto::Udp;
    const char* srcHost = "";
    uint16_t    srcPort = SIP_UDP_PORT;
    if (msg.viaCount > 0) {
        proto   = Transport::protoFromVia(msg.via[0].transport.c_str());
        srcHost = msg.via[0].received.empty()
                ? msg.via[0].host.c_str() : msg.via[0].received.c_str();
        srcPort = msg.via[0].rportVal ? msg.via[0].rportVal
                : (msg.via[0].port    ? msg.via[0].port : SIP_UDP_PORT);
    }
    switch (msg.method) {
    case Method::REGISTER: handleRegister(id,msg,srcHost,srcPort,proto); break;
    case Method::INVITE:   handleInvite  (id,msg,srcHost,srcPort,proto); break;
    case Method::BYE:      handleBye     (id,msg);                       break;
    case Method::CANCEL:   handleCancel  (id,msg);                       break;
    case Method::OPTIONS:  handleOptions (id,msg);                       break;
    case Method::MESSAGE:  handleMessage (id,msg);                       break;
    default:
        sendResponse(id,405,"Method Not Allowed");
        break;
    }
}

void SipServer::onTxnResponse(TxnId id, const SipMessage& msg) {
    // B2BUA: leg-B response?
    if (cfg_.b2buaMode) {
        B2buaCall* c = findB2buaByLegB(id);
        if (c) { b2buaLegBResponse(*c,msg); return; }
    } else {
        // Proxy: leg-B response?
        ProxyCall* c = findProxyByLegB(id);
        if (c) { proxyResponse(*c,msg); return; }
    }
}
void SipServer::onTxnTerminated(TxnId /*id*/) {}

// ── REGISTER handler ──────────────────────────────────────────────────────────
void SipServer::handleRegister(TxnId txnId, const SipMessage& msg,
                                const char* srcHost, uint16_t srcPort, Proto proto) {
    int64_t now = nowMs();

    // Require auth?
    if (cfg_.requireRegAuth) {
        if (msg.authorization.empty()) {
            // Issue 401 challenge
            char ch[512]; buildChallenge(ch,sizeof ch,false);
            SipMessage r=msg.makeResponse(401,"Unauthorized");
            r.wwwAuth.assign(ch,strlen(ch));
            txn_.sendResponse(txnId,r); return;
        }
        // Verify credentials
        auto authStr = msg.authorization.c_str();
        auto parsed  = auth::parseChallenge(authStr, strlen(authStr));
        if (!parsed.ok()) { sendResponse(txnId,400,"Bad Request"); return; }

        // Extract all credential fields from the Authorization header
        auto extractQuoted = [&](const char* key, char* out, size_t outSz) {
            const char* p = strstr(authStr, key);
            if (!p) return;
            p += strlen(key);
            const char* e = strchr(p, '"');
            if (!e) return;
            size_t l = (size_t)(e - p);
            if (l >= outSz) l = outSz - 1;
            strncpy(out, p, l); out[l] = '\0';
        };
        auto extractUnquoted = [&](const char* key, char* out, size_t outSz) {
            const char* p = strstr(authStr, key);
            if (!p) return;
            p += strlen(key);
            // value ends at comma, whitespace, or end of string
            size_t l = 0;
            while (p[l] && p[l] != ',' && p[l] != ' ' && p[l] != '\r' && p[l] != '\n') ++l;
            if (l >= outSz) l = outSz - 1;
            strncpy(out, p, l); out[l] = '\0';
        };

        char username[64]  = {};
        char uri[256]      = {};
        char responseHex[64]= {};
        char cnonceVal[64] = {};
        char ncVal[16]     = {};
        char qopVal[16]    = {};

        extractQuoted  ("username=\"",  username,    sizeof username);
        extractQuoted  ("uri=\"",       uri,         sizeof uri);
        extractQuoted  ("response=\"",  responseHex, sizeof responseHex);
        extractQuoted  ("cnonce=\"",    cnonceVal,   sizeof cnonceVal);
        extractUnquoted("nc=",          ncVal,        sizeof ncVal);
        extractQuoted  ("qop=",         qopVal,       sizeof qopVal);
        // qop may appear unquoted: qop=auth
        if (!qopVal[0]) extractUnquoted("qop=", qopVal, sizeof qopVal);

        uint32_t nc = (uint32_t)strtoul(ncVal, nullptr, 16);
        if (!nc) nc = 1; // default if missing

        if (!validateNonce(parsed->nonce.c_str(), now)) {
            char ch[512]; buildChallenge(ch,sizeof ch,false);
            SipMessage r=msg.makeResponse(401,"Unauthorized");
            r.wwwAuth.assign(ch,strlen(ch));
            txn_.sendResponse(txnId,r); return;
        }

        if (!users_.verifyDigest(username, *parsed, Method::REGISTER, uri,
                                  responseHex, nc,
                                  cnonceVal[0] ? cnonceVal : nullptr,
                                  qopVal[0]    ? qopVal    : nullptr)) {
            sendResponse(txnId,403,"Forbidden"); return;
        }
    }

    // Get AOR from To header — normalise the host to cfg_.domain so that
    // registrations via IP (e.g. sip:101@192.168.32.2) and registrations via
    // hostname (e.g. sip:101@pbx.local) share one canonical AOR in the DB,
    // and INVITE lookups that also use cfg_.domain find them correctly.
    char aor[256];
    {
        auto toSipUri = SipUri::parse(msg.to.uri.c_str());
        if (toSipUri.ok() && !toSipUri->user.empty())
            snprintf(aor, sizeof aor, "sip:%s@%s",
                     toSipUri->user.c_str(), cfg_.domain.c_str());
        else
            snprintf(aor, sizeof aor, "%s", msg.to.uri.c_str());
    }

    // Determine expires
    uint32_t expires = msg.expires;
    if (!expires && msg.hasContact) expires = cfg_.defaultExpires;
    expires = std::min(expires, cfg_.maxExpires);
    if (expires > 0 && expires < cfg_.minExpires) {
        // 423 Interval Too Brief
        SipMessage r=msg.makeResponse(423,"Interval Too Brief");
        r.minExpires = (int)cfg_.minExpires;
        txn_.sendResponse(txnId,r); return;
    }

    // star-contact (*) = unregister all
    bool starContact = false;
    if (msg.hasContact && msg.contact.uri.len==1 && msg.contact.uri.buf[0]=='*')
        starContact = true;

    if (starContact && expires==0) {
        reg_.unregisterAll(aor);
        SipMessage ok=msg.makeResponse(200,"OK"); ok.expires=0;
        txn_.sendResponse(txnId,ok);
        if (cbs_.onRegister) cbs_.onRegister(aor,"*",false);
        return;
    }

    if (msg.hasContact && !starContact) {
        const char* contact = msg.contact.uri.c_str();
        // Use received address for NAT traversal
        char effectiveContact[256];
        snprintf(effectiveContact,sizeof effectiveContact,"%s",contact);

        reg_.update(aor, effectiveContact, srcHost, srcPort, proto,
                    expires, msg.callId.c_str(), msg.cseq.seq, now);

        if (cbs_.onRegister) cbs_.onRegister(aor, effectiveContact, expires>0);
    }

    // Build 200 OK with Contact list
    SipMessage ok = msg.makeResponse(200,"OK");
    ok.expires = expires;
    if (msg.hasContact) {
        char cb[256]; snprintf(cb,sizeof cb,"%s;expires=%u",
                               msg.contact.uri.c_str(), expires);
        ok.contact.uri.assign(cb,strlen(cb)); ok.hasContact=true;
    }
    txn_.sendResponse(txnId,ok);
    printf("[REG] %s  contact=%s  expires=%us\n",
           aor, msg.hasContact?msg.contact.uri.c_str():"(none)", expires);
}

// ── INVITE handler ────────────────────────────────────────────────────────────
void SipServer::handleInvite(TxnId txnId, const SipMessage& msg,
                              const char* srcHost, uint16_t srcPort, Proto proto) {
    int64_t now = nowMs();
    (void)srcHost; (void)srcPort;

    // Send 100 Trying immediately
    SipMessage trying=msg.makeResponse(100,"Trying");
    txn_.sendResponse(txnId,trying);

    // Auth check for calls
    if (cfg_.requireCallAuth) {
        if (msg.authorization.empty() && msg.proxyAuthorization.empty()) {
            char ch[512]; buildChallenge(ch,sizeof ch,true);
            SipMessage r=msg.makeResponse(407,"Proxy Authentication Required");
            r.proxyAuth.assign(ch,strlen(ch));
            txn_.sendResponse(txnId,r); return;
        }
        // (Verification logic analogous to REGISTER; omitted for brevity)
    }

    // Extract callee
    auto toUri = SipUri::parse(msg.requestUri.c_str());
    if (!toUri.ok()) { sendResponse(txnId,400,"Bad Request"); return; }

    // Application callback — allow rejection
    if (cbs_.onCallAttempt) {
        if (!cbs_.onCallAttempt(msg.from.uri.c_str(), msg.requestUri.c_str())) {
            sendResponse(txnId,403,"Forbidden"); return;
        }
    }

    // Local domain → look up in registrar
    if (isLocal(toUri->host.c_str())) {
        char aor[256];
        snprintf(aor,sizeof aor,"sip:%s@%s",
                 toUri->user.c_str(), cfg_.domain.c_str());
        RegBinding binding;
        if (reg_.findBindings(aor, &binding, 1, now) == 0) {
            // 404 Not Found or 480 Temporarily Unavailable
            sendResponse(txnId,404,"Not Found"); return;
        }
        if (cfg_.b2buaMode)
            b2buaInvite(txnId, msg, binding, proto);
        else
            proxyInvite(txnId, msg, binding, proto);
        return;
    }

    // Foreign domain → outbound proxy or reject
    if (!cfg_.outboundProxy.empty()) {
        RegBinding gw;
        gw.contact=msg.requestUri; gw.used=true;
        gw.srcAddr.assign(cfg_.outboundProxy.c_str(),cfg_.outboundProxy.len); gw.srcPort=cfg_.outboundProxyPort;
        gw.proto=cfg_.outboundProto;
        if (cfg_.b2buaMode)
            b2buaInvite(txnId,msg,gw,proto);
        else
            proxyInvite(txnId,msg,gw,proto);
        return;
    }

    sendResponse(txnId,604,"Does Not Exist Anywhere");
}

// ── Proxy mode ────────────────────────────────────────────────────────────────
void SipServer::proxyInvite(TxnId legATxn, const SipMessage& invite,
                             const RegBinding& target, Proto /*proto*/) {
    ProxyCall* call = allocProxy(); if (!call) { sendResponse(legATxn,503,"Service Unavailable"); return; }
    call->legATxn = legATxn;
    call->callerUri.assign(invite.from.uri.c_str(), invite.from.uri.len);
    call->calleeUri.assign(invite.requestUri.c_str(), invite.requestUri.len);
    call->callId   = invite.callId;
    call->startMs  = nowMs();
    call->state    = CallState::Calling;

    // Save caller's top Via for response restoration
    if (invite.viaCount > 0) call->legAVia = invite.via[0];

    // Build forwarded INVITE: strip top Via, add our Via + Record-Route
    SipMessage fwd = invite;
    // Shift Vias down (remove ours if it was there, shouldn't be)
    // Add our own Via on top
    Branch br; genBranch(br);
    for (int i=fwd.viaCount; i>0; --i) fwd.via[i]=fwd.via[i-1];
    fwd.via[0].host = cfg_.localAddr;
    fwd.via[0].port = cfg_.port;
    fwd.via[0].branch = br;
    fwd.via[0].transport.assign(target.proto==Proto::Tcp?"TCP":"UDP",3);
    fwd.viaCount = std::min(fwd.viaCount+1, SIP_MAX_VIA);
    fwd.maxForwards = (fwd.maxForwards > 0) ? fwd.maxForwards-1 : 0;
    addRecordRoute(fwd);

    // Route to target
    const char* dst = target.srcAddr.empty() ? target.contact.c_str() : target.srcAddr.c_str();
    uint16_t    dstPort = target.srcPort ? target.srcPort : SIP_UDP_PORT;
    auto parsed = SipUri::parse(target.contact.c_str());
    if (parsed.ok() && !parsed->host.empty()) {
        dst     = parsed->host.c_str();
        dstPort = parsed->effectivePort();
    }
    bool udp = target.proto == Proto::Udp;
    call->legBTxn = txn_.sendRequest(fwd, dst, dstPort, udp);
    if (call->legBTxn == InvalidTxn) {
        freeProxy(*call); sendResponse(legATxn,503,"Service Unavailable");
    }
}

void SipServer::proxyResponse(ProxyCall& call, const SipMessage& resp) {
    if (resp.isProvisional()) {
        // Forward 180/183 upstream: strip our Via, forward
        SipMessage fwd = resp;
        if (fwd.viaCount > 1) {
            for (int i=0;i+1<fwd.viaCount;++i) fwd.via[i]=fwd.via[i+1];
            --fwd.viaCount;
        }
        // Find leg-A txn and send response upstream
        // (txn layer doesn't support injecting responses into server txns easily;
        //  send raw via transport using call->legAVia)
        char buf[SIP_MAX_MSG]; size_t n = fwd.format(buf, sizeof buf);
        if (n) {
            const char* dst = call.legAVia.received.empty()
                            ? call.legAVia.host.c_str()
                            : call.legAVia.received.c_str();
            uint16_t dstPort = call.legAVia.rportVal ? call.legAVia.rportVal
                             : (call.legAVia.port    ? call.legAVia.port : SIP_UDP_PORT);
            Proto proto = Transport::protoFromVia(call.legAVia.transport.c_str());
            sendRaw(buf,n,dst,dstPort,proto);
        }
        if (resp.statusCode==180) call.state=CallState::Ringing;
        return;
    }

    if (resp.is2xx()) {
        call.state = CallState::Connected;
        // Forward 200 OK upstream
        SipMessage fwd = resp;
        if (fwd.viaCount > 1) {
            for (int i=0;i+1<fwd.viaCount;++i) fwd.via[i]=fwd.via[i+1];
            --fwd.viaCount;
        }
        char buf[SIP_MAX_MSG]; size_t n = fwd.format(buf,sizeof buf);
        if (n) {
            const char* dst = call.legAVia.received.empty()
                            ? call.legAVia.host.c_str()
                            : call.legAVia.received.c_str();
            uint16_t dstPort = call.legAVia.rportVal ? call.legAVia.rportVal
                             : (call.legAVia.port    ? call.legAVia.port : SIP_UDP_PORT);
            Proto proto = Transport::protoFromVia(call.legAVia.transport.c_str());
            sendRaw(buf,n,dst,dstPort,proto);
        }
        return;
    }

    // Final non-2xx: forward upstream and clean up
    SipMessage fwd = resp;
    if (fwd.viaCount > 1) {
        for (int i=0;i+1<fwd.viaCount;++i) fwd.via[i]=fwd.via[i+1]; --fwd.viaCount;
    }
    char buf[SIP_MAX_MSG]; size_t n=fwd.format(buf,sizeof buf);
    if (n) {
        const char* dst = call.legAVia.received.empty()
                        ? call.legAVia.host.c_str()
                        : call.legAVia.received.c_str();
        uint16_t dstPort = call.legAVia.rportVal ? call.legAVia.rportVal
                         : (call.legAVia.port    ? call.legAVia.port : SIP_UDP_PORT);
        Proto proto = Transport::protoFromVia(call.legAVia.transport.c_str());
        sendRaw(buf,n,dst,dstPort,proto);
    }

    CdrRecord cdr;
    cdr.callId  = call.callId;
    cdr.fromUri = call.callerUri;
    cdr.toUri   = call.calleeUri;
    cdr.outbound= false;
    cdr.startMs = call.startMs;
    cdr.endMs   = nowMs();
    cdr.sipCode = resp.statusCode;
    cdr.result  = (resp.statusCode==486||resp.statusCode==600)
                ? CdrResult::Busy : CdrResult::Rejected;
    cdr_.write(cdr);
    if (cbs_.onCallEnd) cbs_.onCallEnd(cdr);
    freeProxy(call);
}

// ── B2BUA mode ────────────────────────────────────────────────────────────────
void SipServer::b2buaInvite(TxnId legATxn, const SipMessage& invite,
                             const RegBinding& target, Proto /*inProto*/) {
    B2buaCall* call = allocB2bua();
    if (!call) { sendResponse(legATxn,503,"Service Unavailable"); return; }

    call->legATxn    = legATxn;
    call->legACallId = invite.callId;
    genTag(call->legALocalTag);
    call->legARemoteTag = invite.from.tag;
    call->callerUri.assign(invite.from.uri.c_str(),invite.from.uri.len);
    call->calleeUri.assign(invite.requestUri.c_str(),invite.requestUri.len);
    call->callId = invite.callId;
    call->startMs= nowMs();
    call->state  = CallState::Calling;

    // Allocate RTP relay ports
    call->rtpAPort = allocRtpPort();
    call->rtpBPort = allocRtpPort();

    // Parse inbound SDP offer (to know caller's RTP address)
    if (invite.body && invite.bodyLen) {
        auto sdp = sip::SdpSession::parse(invite.body, invite.bodyLen);
        if (sdp.ok()) {
            const sip::MediaSection* am = sdp->audioMedia();
            if (am) {
                strncpy(call->callerRtpAddr,
                        sdp->connAddr.empty() ? invite.via[0].host.c_str()
                                              : sdp->connAddr.c_str(),
                        sizeof call->callerRtpAddr - 1);
                call->callerRtpPort = am->port;
                call->callerPayloadType = am->codecCount ? am->codecs[0].pt : 0;
                if (am->codecCount && !am->codecs[0].encoding.empty()) {
                    call->callerCodecName.assign(am->codecs[0].encoding.c_str(),
                                                 am->codecs[0].encoding.len);
                }
            }
        }
    }

    // Send 100 Trying (already sent by handleInvite)

    // Build outbound INVITE (leg B)
    SipMessage fwd; fwd.isRequest=true; fwd.method=Method::INVITE;
    fwd.requestUri.assign(invite.requestUri.c_str(),invite.requestUri.len);

    // Use the routable IP in all SIP headers (Via, From, Contact, Call-ID).
    // cfg_.rtpLocalAddr is always set to a reachable NIC IP after init().
    const char* la = cfg_.rtpLocalAddr.empty()
                   ? cfg_.localAddr.c_str() : cfg_.rtpLocalAddr.c_str();

    char furi[256]; snprintf(furi,sizeof furi,"sip:pbx@%s",la);
    fwd.from.uri.assign(furi,strlen(furi));
    genTag(call->legBLocalTag); fwd.from.tag=call->legBLocalTag;
    // Request-URI = callee's registered contact (not the original request-URI)
    fwd.requestUri.assign(target.contact.c_str(),target.contact.len);
    // To = callee's AOR (from original invite)
    fwd.to.uri.assign(invite.to.uri.c_str(),invite.to.uri.len);
    genCallId(call->legBCallId); fwd.callId=call->legBCallId;
    fwd.cseq={call->legBCSeq++, Method::INVITE};
    fwd.maxForwards=70;
    Branch br; genBranch(br);
    fwd.via[0].host.assign(la,strlen(la)); fwd.via[0].port=cfg_.port;
    fwd.via[0].branch=br; fwd.via[0].transport.assign("UDP",3);
    fwd.viaCount=1;
    char contact[256]; snprintf(contact,sizeof contact,"<sip:pbx@%s:%u>",la,cfg_.port);
    fwd.contact.uri.assign(contact,strlen(contact)); fwd.hasContact=true;
    fwd.allow.assign("INVITE,ACK,BYE,CANCEL,OPTIONS",30);
    fwd.userAgent.assign("sip_server/1.0",14);

    // Rewrite SDP: offer our relay port (rtpBPort) to callee
    const char* relayAddr = cfg_.rtpLocalAddr.empty()
                          ? cfg_.localAddr.c_str() : cfg_.rtpLocalAddr.c_str();
    if (invite.body && invite.bodyLen) {
        size_t sdpLen = rewriteSdp(invite.body, invite.bodyLen,
                                   relayAddr, call->rtpBPort,
                                   sdpBuf_, sizeof sdpBuf_);
        if (sdpLen) {
            fwd.body=sdpBuf_; fwd.bodyLen=sdpLen;
            fwd.contentType.assign("application/sdp",15);
            fwd.contentLen=(uint32_t)sdpLen;
        }
    }

    // Route to target
    const char* dst     = target.srcAddr.empty() ? target.contact.c_str()
                                                  : target.srcAddr.c_str();
    uint16_t    dstPort = target.srcPort ? target.srcPort : SIP_UDP_PORT;
    auto parsedContact = SipUri::parse(target.contact.c_str());
    if (parsedContact.ok() && !parsedContact->host.empty()) {
        dst     = parsedContact->host.c_str();
        dstPort = parsedContact->effectivePort();
    }
    call->legBTxn = txn_.sendRequest(fwd, dst, dstPort, target.proto==Proto::Udp);
    if (call->legBTxn == InvalidTxn) {
        freeB2bua(*call); sendResponse(legATxn,503,"Service Unavailable");
    }
}

// Build a correctly-formed response for leg A by re-parsing the original
// INVITE that the caller sent us.  This guarantees Via / From / To /
// Call-ID match exactly what the caller expects — no guesswork.
static SipMessage makeLegAResponse(TransactionLayer& txn, TxnId legATxn,
                                   int code, const char* reason) {
    const Transaction* t = txn.findById(legATxn);
    if (t) {
        auto req = SipMessage::parse(t->reqBuf, t->reqLen);
        if (req.ok()) return req->makeResponse(code, reason);
    }
    // Fallback (should never happen): bare minimum without Via
    SipMessage r;
    r.isRequest = false; r.statusCode = code;
    r.reason.assign(reason, strlen(reason));
    return r;
}

void SipServer::b2buaLegBResponse(B2buaCall& call, const SipMessage& resp) {
    if (resp.isProvisional()) {
        if (resp.statusCode == 180 || resp.statusCode == 183) {
            call.state = CallState::Ringing;
            // Forward ringing upstream with proper Via from the stored INVITE.
            SipMessage ring = makeLegAResponse(txn_, call.legATxn,
                                               resp.statusCode, resp.reason.c_str());
            // Use the server's own leg-A tag (not the callee's tag) so that
            // the caller's early-dialog To-tag stays consistent with the 200 OK.
            ring.to.tag = call.legALocalTag;
            txn_.sendResponse(call.legATxn, ring);
        }
        return;
    }

    if (resp.is2xx()) {
        call.state     = CallState::Connected;
        call.connectMs = nowMs();
        call.legBRemoteTag = resp.to.tag;

        // Save callee's Contact for ACK routing and subsequent BYE.
        if (resp.hasContact && !resp.contact.uri.empty())
            call.calleeTarget = resp.contact.uri;

        // Parse callee SDP answer to get their RTP address
        if (resp.body && resp.bodyLen) {
            auto sdp = sip::SdpSession::parse(resp.body, resp.bodyLen);
            if (sdp.ok()) {
                const sip::MediaSection* am = sdp->audioMedia();
                if (am) {
                    strncpy(call.calleeRtpAddr,
                            sdp->connAddr.empty() ? resp.contact.uri.c_str()
                                                  : sdp->connAddr.c_str(),
                            sizeof call.calleeRtpAddr-1);
                    call.calleeRtpPort = am->port;
                    call.calleePayloadType = am->codecCount ? am->codecs[0].pt : 0;
                    if (am->codecCount && !am->codecs[0].encoding.empty()) {
                        call.calleeCodecName.assign(am->codecs[0].encoding.c_str(),
                                                    am->codecs[0].encoding.len);
                    }
                }
            }
        }

        // Open RTP relay
        openRtpRelay(call);

        // Build 200 OK for leg A by re-parsing the stored INVITE so the
        // response carries the exact Via / From / To / Call-ID the caller
        // expects — identical to what 180 Ringing used above.
        const char* relayAddr = cfg_.rtpLocalAddr.empty()
                              ? cfg_.localAddr.c_str() : cfg_.rtpLocalAddr.c_str();
        SipMessage ok = makeLegAResponse(txn_, call.legATxn, 200, "OK");
        // Overwrite the To-tag with our stable leg-A local tag.
        ok.to.tag = call.legALocalTag;
        // Provide our routable Contact so the caller can send ACK / BYE to us.
        const char* la2 = cfg_.rtpLocalAddr.empty()
                        ? cfg_.localAddr.c_str() : cfg_.rtpLocalAddr.c_str();
        char contact2[256];
        snprintf(contact2,sizeof contact2,"<sip:pbx@%s:%u>",la2,cfg_.port);
        ok.contact.uri.assign(contact2,strlen(contact2)); ok.hasContact=true;
        ok.allow.assign("INVITE,ACK,BYE,CANCEL,OPTIONS",30);
        // Attach callee SDP rewritten with our relay address and caller-side port.
        if (resp.body && resp.bodyLen) {
            size_t sdpLen = rewriteSdp(resp.body, resp.bodyLen,
                                       relayAddr, call.rtpAPort,
                                       sdpBuf_, sizeof sdpBuf_);
            if (sdpLen) {
                ok.body=sdpBuf_; ok.bodyLen=sdpLen;
                ok.contentType.assign("application/sdp",15);
                ok.contentLen=(uint32_t)sdpLen;
            }
        }
        txn_.sendResponse(call.legATxn, ok);
        printf("[B2BUA] Call connected  %s → %s\n",
               call.callerUri.c_str(), call.calleeUri.c_str());
        return;
    }

    // Final non-2xx: reject leg A with a properly-formed response.
    SipMessage r = makeLegAResponse(txn_, call.legATxn,
                                    resp.statusCode, resp.reason.c_str());
    txn_.sendResponse(call.legATxn, r);

    CdrRecord cdr;
    cdr.callId=call.callId; cdr.fromUri=call.callerUri; cdr.toUri=call.calleeUri;
    cdr.outbound=false; cdr.startMs=call.startMs; cdr.endMs=nowMs();
    cdr.sipCode=resp.statusCode;
    cdr.result=(resp.statusCode==486||resp.statusCode==600)?CdrResult::Busy:CdrResult::Rejected;
    cdr_.write(cdr);
    if (cbs_.onCallEnd) cbs_.onCallEnd(cdr);
    freeB2bua(call);
}

// ── ACK, BYE, CANCEL, OPTIONS, MESSAGE ───────────────────────────────────────
void SipServer::handleAck(const SipMessage& msg) {
    if (!cfg_.b2buaMode) return;  // Proxy: ACK routed by Record-Route
    B2buaCall* call = findB2buaByCallId(msg.callId);
    if (!call) return;
    // Forward ACK to leg B
    // Destination: use Contact from callee's 200 OK (calleeTarget), else AOR.
    const char* dstUriStr = call->calleeTarget.empty()
                          ? call->calleeUri.c_str()
                          : call->calleeTarget.c_str();
    // Strip angle-brackets if present (<sip:...>).
    char stripped[256]; strncpy(stripped, dstUriStr, sizeof stripped-1); stripped[sizeof stripped-1]=0;
    char* uriStart = stripped;
    if (stripped[0]=='<') {
        uriStart = stripped+1;
        char* gt=strchr(uriStart,'>'); if(gt)*gt=0;
    }
    auto dstParsed = SipUri::parse(uriStart);
    if (!dstParsed.ok()) return;

    const char* la = cfg_.rtpLocalAddr.empty()
                   ? cfg_.localAddr.c_str() : cfg_.rtpLocalAddr.c_str();
    SipMessage fwd = msg;
    Branch br; genBranch(br);
    fwd.via[0].host.assign(la,strlen(la)); fwd.via[0].port=cfg_.port;
    fwd.via[0].branch=br; fwd.via[0].transport.assign("UDP",3);
    fwd.from.tag=call->legBLocalTag;
    fwd.callId=call->legBCallId;
    fwd.cseq.method=Method::ACK;
    // Request-URI of ACK = callee's Contact URI
    fwd.requestUri.assign(uriStart,strlen(uriStart));
    // Send directly (ACK for 2xx is outside transaction layer)
    char buf[SIP_MAX_MSG]; size_t n=fwd.format(buf,sizeof buf);
    if (n) sendRaw(buf,n,dstParsed->host.c_str(),dstParsed->effectivePort(),Proto::Udp);
}

void SipServer::handleBye(TxnId txnId, const SipMessage& msg) {
    sendResponse(txnId, 200, "OK");

    if (cfg_.b2buaMode) {
        B2buaCall* call = findB2buaByCallId(msg.callId);
        if (!call) return;
        // Send BYE to the other leg
        SipMessage bye; bye.isRequest=true; bye.method=Method::BYE;
        bye.requestUri=call->calleeTarget.empty()?call->calleeUri:call->calleeTarget;
        bye.from.uri.assign("sip:server@",11); bye.from.uri.append(cfg_.localAddr.c_str(),cfg_.localAddr.len);
        bye.from.tag=call->legBLocalTag;
        bye.to.uri=call->calleeUri; bye.to.tag=call->legBRemoteTag;
        bye.callId=call->legBCallId; bye.cseq={call->legBCSeq++,Method::BYE};
        bye.maxForwards=70;
        Branch br; genBranch(br);
        bye.via[0].host=cfg_.localAddr; bye.via[0].port=cfg_.port;
        bye.via[0].branch=br; bye.via[0].transport.assign("UDP",3);
        bye.viaCount=1;
        auto uri=SipUri::parse(bye.requestUri.c_str());
        if (uri.ok()) txn_.sendRequest(bye,uri->host.c_str(),uri->effectivePort(),true);

        CdrRecord cdr;
        cdr.callId=call->callId; cdr.fromUri=call->callerUri; cdr.toUri=call->calleeUri;
        cdr.outbound=false; cdr.startMs=call->startMs; cdr.connectMs=call->connectMs;
        cdr.endMs=nowMs(); cdr.sipCode=200; cdr.result=CdrResult::Answered;
        cdr_.write(cdr);
        if (cbs_.onCallEnd) cbs_.onCallEnd(cdr);
        freeB2bua(*call);
    } else {
        // Proxy: forward BYE downstream (it will route via Record-Route normally)
        // The UAs handle this directly via Route headers; nothing for us to do here
        // unless we want to log the BYE
        ProxyCall* call = findProxyByCallId(msg.callId);
        if (!call) return;
        CdrRecord cdr;
        cdr.callId=call->callId; cdr.fromUri=call->callerUri; cdr.toUri=call->calleeUri;
        cdr.outbound=false; cdr.startMs=call->startMs; cdr.endMs=nowMs();
        cdr.sipCode=200; cdr.result=CdrResult::Answered;
        cdr_.write(cdr);
        if (cbs_.onCallEnd) cbs_.onCallEnd(cdr);
        freeProxy(*call);
    }
}

void SipServer::handleCancel(TxnId txnId, const SipMessage& msg) {
    // NOTE: the transaction layer already sent 200 OK to the CANCEL NIST and
    // calls us with txnId = the INVITE IST id.  Do NOT call sendResponse()
    // here for the CANCEL — that was the old bug that sent 200 OK for the
    // *INVITE* and destroyed the IST before we could send 487.
    //
    // txnId here IS the INVITE IST.  Send 487 to it so the caller's ICT
    // transitions from Completed to Confirmed and eventually terminates.

    if (cfg_.b2buaMode) {
        B2buaCall* call = findB2buaByCallId(msg.callId);
        // Accept CANCEL during Calling (no provisional yet) and Ringing states.
        if (call && (call->state == CallState::Calling ||
                     call->state == CallState::Ringing)) {
            if (call->legBTxn != InvalidTxn) txn_.cancelInvite(call->legBTxn);
            // 487 to leg A — built from the stored INVITE so Via headers are correct.
            SipMessage r = makeLegAResponse(txn_, txnId,
                                            487, "Request Terminated");
            r.to.tag = call->legALocalTag;  // must be stable across responses
            txn_.sendResponse(txnId, r);

            CdrRecord cdr;
            cdr.callId  = call->callId;  cdr.fromUri = call->callerUri;
            cdr.toUri   = call->calleeUri;
            cdr.startMs = call->startMs; cdr.endMs   = nowMs();
            cdr.sipCode = 487;           cdr.result  = CdrResult::Cancelled;
            cdr_.write(cdr);
            if (cbs_.onCallEnd) cbs_.onCallEnd(cdr);
            freeB2bua(*call);
        }
    } else {
        ProxyCall* call = findProxyByCallId(msg.callId);
        if (call && call->legBTxn!=InvalidTxn) {
            txn_.cancelInvite(call->legBTxn);
            // Send 487 to the INVITE IST so the caller gets a proper rejection.
            SipMessage r = makeLegAResponse(txn_, txnId,
                                            487, "Request Terminated");
            txn_.sendResponse(txnId, r);
            CdrRecord cdr;
            cdr.callId=call->callId; cdr.fromUri=call->callerUri; cdr.toUri=call->calleeUri;
            cdr.startMs=call->startMs; cdr.endMs=nowMs();
            cdr.sipCode=487; cdr.result=CdrResult::Cancelled;
            cdr_.write(cdr);
            if (cbs_.onCallEnd) cbs_.onCallEnd(cdr);
            freeProxy(*call);
        }
    }
}

void SipServer::handleOptions(TxnId txnId, const SipMessage& msg) {
    SipMessage ok=msg.makeResponse(200,"OK");
    ok.allow.assign("INVITE,ACK,BYE,CANCEL,OPTIONS,REGISTER,MESSAGE",47);
    ok.supported.assign("timer,replaces",14);
    txn_.sendResponse(txnId,ok);
}

void SipServer::handleMessage(TxnId txnId, const SipMessage& msg) {
    sendResponse(txnId,200,"OK");
    // Optionally route MESSAGE like a proxy; for now just accept
}

// ── Auth helpers ──────────────────────────────────────────────────────────────
namespace auth { void md5Hex(const void*, size_t, char[33]); }

void SipServer::issueNonce(char out[33]) {
    // nonce = MD5(timestamp:secret:random)
    char tmp[128]; int64_t now=nowMs();
    snprintf(tmp,sizeof tmp,"%lld:%s:%08x",
             (long long)now, cfg_.nonceSecret.c_str(), rnd32());
    auth::md5Hex(tmp,strlen(tmp),out);
    // Cache for validation
    auto& slot = nonceCache_[nonceIdx_ % NonceCache];
    strncpy(slot.val,out,32); slot.issueMs=now;
    ++nonceIdx_;
}

bool SipServer::validateNonce(const char* nonce, int64_t nowMs) {
    // Accept any nonce issued in the last 5 minutes
    for (auto& s : nonceCache_) {
        if (s.issueMs>0 && strcmp(s.val,nonce)==0) {
            return (nowMs - s.issueMs) < 300000LL; // 5 min
        }
    }
    return false;
}

void SipServer::buildChallenge(char* buf, size_t sz, bool proxy) {
    char nonce[33]; issueNonce(nonce);
    const char* hdr = proxy ? "Proxy-Authenticate" : "WWW-Authenticate";
    (void)hdr;
    snprintf(buf,sz,"Digest realm=\"%s\", nonce=\"%s\", algorithm=MD5, qop=\"auth\"",
             cfg_.realm.c_str(), nonce);
}

bool SipServer::checkAuth(const SipMessage& /*msg*/, Method /*m*/, bool /*proxy*/) {
    return true; // simplified; full impl analogous to REGISTER
}

// ── Record-Route insertion (proxy mode) ──────────────────────────────────────
void SipServer::addRecordRoute(SipMessage& msg) const {
    char rr[256];
    snprintf(rr,sizeof rr,"<sip:%s:%u;lr>",cfg_.localAddr.c_str(),cfg_.port);
    if (msg.recordRoute.empty()) msg.recordRoute.assign(rr,strlen(rr));
    else { char tmp[512]; snprintf(tmp,sizeof tmp,"%s, %s",rr,msg.recordRoute.c_str());
           msg.recordRoute.assign(tmp,strlen(tmp)); }
}

// ── SDP rewrite for B2BUA ────────────────────────────────────────────────────
// Replaces the first c= and first m=audio lines with new addr:port.
size_t SipServer::rewriteSdp(const char* orig, size_t len,
                              const char* newAddr, uint16_t newPort,
                              char* out, size_t outSz) {
    size_t n=0;
    const char* p=orig, *end=orig+len;
    bool cReplaced=false, mReplaced=false;
    while (p<end && n<outSz-128) {
        const char* nl=(const char*)memchr(p,'\n',(size_t)(end-p));
        size_t ll=nl?(size_t)(nl-p+1):(size_t)(end-p);
        const char* line=p; p=(nl?nl+1:end);
        // Replace c= line
        if (!cReplaced && ll>=2 && line[0]=='c' && line[1]=='=') {
            n+=(size_t)snprintf(out+n,outSz-n,"c=IN IP4 %s\r\n",newAddr);
            cReplaced=true; continue;
        }
        // Replace first m=audio port
        if (!mReplaced && ll>=9 && strncmp(line,"m=audio ",8)==0) {
            const char* sp=line+8;
            while(sp<line+ll && *sp!=' ')++sp;
            n+=(size_t)snprintf(out+n,outSz-n,"m=audio %u%s",newPort,sp);
            mReplaced=true; continue;
        }
        // Copy line verbatim
        if (n+ll < outSz) { memcpy(out+n,line,ll); n+=ll; }
    }
    out[n]=0; return n;
}

// ── RTP relay (B2BUA) ────────────────────────────────────────────────────────
uint16_t SipServer::allocRtpPort() {
    uint16_t p = nextRtpPort_;
    nextRtpPort_ = (uint16_t)(nextRtpPort_ + 2);
    if (nextRtpPort_ < cfg_.rtpBasePort) nextRtpPort_=cfg_.rtpBasePort;
    return p;
}

bool SipServer::openRtpRelay(B2buaCall& call) {
    // Open relay socket A (faces caller)
    int fa = socket(AF_INET,SOCK_DGRAM,0);
    int fb = socket(AF_INET,SOCK_DGRAM,0);
    if (fa<0||fb<0) { if(fa>=0)close(fa); if(fb>=0)close(fb); return false; }
    auto bind_udp = [](int fd, const char* addr, uint16_t port) -> bool {
        struct sockaddr_in sa{}; sa.sin_family=AF_INET; sa.sin_port=htons(port);
        sa.sin_addr.s_addr=addr&&*addr?inet_addr(addr):INADDR_ANY;
        return ::bind(fd,(sockaddr*)&sa,sizeof sa)==0;
    };
    const char* la = cfg_.rtpLocalAddr.empty()?cfg_.localAddr.c_str():cfg_.rtpLocalAddr.c_str();
    if (!bind_udp(fa,la,call.rtpAPort)||!bind_udp(fb,la,call.rtpBPort)) {
        close(fa);close(fb); return false;
    }
    call.rtpAFd=fa; call.rtpBFd=fb;

    // Two relay threads: A→B and B→A
    // Build per-thread argument blocks.  Ownership transfers to the threads;
    // pointers are also saved in B2buaCall so closeRtpRelay can signal them.
    auto* argAB = new RtpRelayArgs{};
    argAB->srcFd   = fa;    argAB->dstFd = fb;
    argAB->dstPort = call.calleeRtpPort;
    argAB->srcPt   = call.callerPayloadType;
    argAB->dstPt   = call.calleePayloadType;
    argAB->srcCodec= resolveCodec(codecs_, call.callerPayloadType, call.callerCodecName.c_str());
    argAB->dstCodec= resolveCodec(codecs_, call.calleePayloadType, call.calleeCodecName.c_str());
    argAB->running = true;
    strncpy(argAB->dstAddr, call.calleeRtpAddr, sizeof(argAB->dstAddr)-1);

    auto* argBA = new RtpRelayArgs{};
    argBA->srcFd   = fb;    argBA->dstFd = fa;
    argBA->dstPort = call.callerRtpPort;
    argBA->srcPt   = call.calleePayloadType;
    argBA->dstPt   = call.callerPayloadType;
    argBA->srcCodec= resolveCodec(codecs_, call.calleePayloadType, call.calleeCodecName.c_str());
    argBA->dstCodec= resolveCodec(codecs_, call.callerPayloadType, call.callerCodecName.c_str());
    argBA->running = true;
    strncpy(argBA->dstAddr, call.callerRtpAddr, sizeof(argBA->dstAddr)-1);

    // Save pointers so closeRtpRelay can set running=false cleanly.
    call.relayArgAB = argAB;
    call.relayArgBA = argBA;

    pthread_t tA, tB;
    pthread_create(&tA, nullptr, rtpRelayThread, argAB);
    pthread_create(&tB, nullptr, rtpRelayThread, argBA);
    pthread_detach(tA);
    pthread_detach(tB);
    call.relayRunning = true;
    printf("[B2BUA] RTP relay open: %s:%u <-> server:%u/%u <-> %s:%u\n",
           call.callerRtpAddr, call.callerRtpPort,
           call.rtpAPort, call.rtpBPort,
           call.calleeRtpAddr, call.calleeRtpPort);
    if (call.callerPayloadType != call.calleePayloadType) {
                printf("[B2BUA] Codec bridge active: PT %u (%s) <-> PT %u (%s)\n",
                             call.callerPayloadType,
                             call.callerCodecName.empty() ? "unknown" : call.callerCodecName.c_str(),
                             call.calleePayloadType,
                             call.calleeCodecName.empty() ? "unknown" : call.calleeCodecName.c_str());
    }
    return true;
}

void SipServer::closeRtpRelay(B2buaCall& call) {
    // Signal relay threads to stop via their own stop-flag.  This is safe
    // even if the B2buaCall slot is immediately reused for a new call,
    // because the flag lives in the heap-allocated RtpRelayArgs block, not
    // in the B2buaCall slot.
    if (call.relayArgAB) { call.relayArgAB->running = false; call.relayArgAB = nullptr; }
    if (call.relayArgBA) { call.relayArgBA->running = false; call.relayArgBA = nullptr; }
    // Closing the sockets will unblock any pending recv() immediately.
    if (call.rtpAFd>=0){::shutdown(call.rtpAFd,SHUT_RDWR);close(call.rtpAFd);call.rtpAFd=-1;}
    if (call.rtpBFd>=0){::shutdown(call.rtpBFd,SHUT_RDWR);close(call.rtpBFd);call.rtpBFd=-1;}
    call.relayRunning=false;
}

void* SipServer::rtpRelayThread(void* arg) {
    auto* a = (RtpRelayArgs*)arg;
    // Short receive timeout so the loop condition is checked regularly.
    struct timeval tv{0, 50000}; // 50 ms
    setsockopt(a->srcFd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    struct sockaddr_in dst{};
    dst.sin_family      = AF_INET;
    dst.sin_port        = htons(a->dstPort);
    dst.sin_addr.s_addr = inet_addr(a->dstAddr);
    uint8_t buf[2048];
    uint8_t out[4096];

    for (;;) {
        if (!a->running) break;          // stop-flag set by closeRtpRelay

        ssize_t n = recv(a->srcFd, buf, sizeof buf, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                continue;                // normal receive timeout — re-check flag
            break;                       // EBADF or other fatal error: socket closed
        }
        if (n == 0) break;               // orderly shutdown

        size_t outLen = (size_t)n;
        const bool canMapPt = (a->srcPt != 0 || a->dstPt != 0);
        bool sent = false;
        if (canMapPt && transcodeRtpPacket(buf, (size_t)n,
                                           out, sizeof out, &outLen,
                                           a->dstPt,
                                           static_cast<ICodec*>(a->srcCodec),
                                           static_cast<ICodec*>(a->dstCodec))) {
            sent = sendto(a->dstFd, out, outLen, 0,
                          (sockaddr*)&dst, sizeof dst) > 0;
        }
        if (!sent)
            sendto(a->dstFd, buf, (size_t)n, 0, (sockaddr*)&dst, sizeof dst);
    }
    delete a;
    return nullptr;
}

// ── Pool management ───────────────────────────────────────────────────────────
ProxyCall* SipServer::allocProxy() {
    for (auto& c:proxyCalls_) if(!c.used){c.used=true;return &c;} return nullptr;
}
void SipServer::freeProxy(ProxyCall& c)      { c.used=false; }
ProxyCall* SipServer::findProxyByLegA(TxnId id) {
    for(auto& c:proxyCalls_) if(c.used&&c.legATxn==id) return &c; return nullptr;
}
ProxyCall* SipServer::findProxyByLegB(TxnId id) {
    for(auto& c:proxyCalls_) if(c.used&&c.legBTxn==id) return &c; return nullptr;
}
ProxyCall* SipServer::findProxyByCallId(const CallId& id) {
    for(auto& c:proxyCalls_) if(c.used&&c.callId==id) return &c; return nullptr;
}

B2buaCall* SipServer::allocB2bua() {
    for(auto& c:b2buaCalls_) if(!c.used){
        // Zero-initialise the slot so stale tags / IDs / FDs from a previous
        // call cannot leak into the new one.
        memset(&c,0,sizeof c);
        c.rtpAFd=-1; c.rtpBFd=-1;
        c.legBTxn=InvalidTxn;
        c.used=true;
        return &c;
    }
    return nullptr;
}
void SipServer::freeB2bua(B2buaCall& c) { closeRtpRelay(c); c.used=false; }
B2buaCall* SipServer::findB2buaByLegA(TxnId id) {
    for(auto& c:b2buaCalls_) if(c.used&&c.legATxn==id) return &c; return nullptr;
}
B2buaCall* SipServer::findB2buaByLegB(TxnId id) {
    for(auto& c:b2buaCalls_) if(c.used&&c.legBTxn==id) return &c; return nullptr;
}
B2buaCall* SipServer::findB2buaByCallId(const CallId& id) {
    for(auto& c:b2buaCalls_) if(c.used&&c.callId==id) return &c; return nullptr;
}

// ── Helpers ───────────────────────────────────────────────────────────────────
bool SipServer::sendResponse(TxnId txn, int code, const char* reason,
                             const char* body, size_t blen, const char* ct) {
    const Transaction* t=txn_.findById(txn); if(!t) return false;
    auto req=SipMessage::parse(t->reqBuf,t->reqLen); if(!req.ok()) return false;
    SipMessage r=req->makeResponse(code,reason);
    if(body&&blen){ r.body=body; r.bodyLen=blen; r.contentLen=(uint32_t)blen;
                    r.contentType.assign(ct,strlen(ct)); }
    return txn_.sendResponse(txn,r);
}

bool SipServer::sendRaw(const char* d, size_t l,
                        const char* h, uint16_t p, Proto proto) {
    return transport_.send(d,l,h,p,proto);
}

// ── Diagnostics ───────────────────────────────────────────────────────────────
void SipServer::printStats() const {
    int64_t now=nowMs();
    printf("\n── SIP Server Stats ─────────────────────────────────────────\n");
    printf("  Domain     : %s\n", cfg_.domain.c_str());
    printf("  Mode       : %s\n", cfg_.b2buaMode?"B2BUA":"Stateful Proxy");
    printf("  Users      : %zu\n", users_.count());
    printf("  Registrations: %zu\n", reg_.totalBindings());
    printf("  Active calls : %zu\n", activeCallCount());
    printf("─────────────────────────────────────────────────────────────\n\n");
    (void)now;
}

void SipServer::printRegistrations() const {
    printf("\n── Active Registrations ─────────────────────────────────────\n");
    reg_.printAll(nowMs());
    printf("─────────────────────────────────────────────────────────────\n\n");
}

void SipServer::printCalls() const {
    printf("\n── Active Calls ─────────────────────────────────────────────\n");
    size_t n=0;
    if (cfg_.b2buaMode) {
        for(const auto& c:b2buaCalls_) if(c.used){
            const char* st="?";
            switch(c.state){case CallState::Calling:st="Calling";break;
                            case CallState::Ringing:st="Ringing";break;
                            case CallState::Connected:st="Connected";break;
                            default:st="Term";break;}
            printf("  [%zu] %s → %s  [%s]\n",++n,c.callerUri.c_str(),c.calleeUri.c_str(),st);
        }
    } else {
        for(const auto& c:proxyCalls_) if(c.used){
            const char* st="?";
            switch(c.state){case CallState::Calling:st="Calling";break;
                            case CallState::Ringing:st="Ringing";break;
                            case CallState::Connected:st="Connected";break;
                            default:st="Term";break;}
            printf("  [%zu] %s → %s  [%s]\n",++n,c.callerUri.c_str(),c.calleeUri.c_str(),st);
        }
    }
    if (!n) printf("  (none)\n");
    printf("─────────────────────────────────────────────────────────────\n\n");
}

void SipServer::printCodecs() const {
    printf("\n── Active Codec Registry ────────────────────────────────────\n");
    codecs_.printAll();
    printf("─────────────────────────────────────────────────────────────\n\n");
}

size_t SipServer::registrationCount() const { return reg_.totalBindings(); }
size_t SipServer::activeCallCount() const {
    size_t n=0;
    for(const auto& c:proxyCalls_)  if(c.used)++n;
    for(const auto& c:b2buaCalls_)  if(c.used)++n;
    return n;
}

} // namespace sip

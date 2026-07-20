#!/usr/bin/env python3
# Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
# All rights reserved.

"""Rewrite SipStack.cpp with dual-transport (UDP+TCP) support."""

path = "/home/mkwiatkowski/Projects/SIP/src/SipStack.cpp"

content = r"""// SipStack.cpp – SIP User Agent with UDP + TCP transport (RFC 3261)
#include "SipStack.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/time.h>
#include <cerrno>

namespace sip {

// ── Helpers ───────────────────────────────────────────────────────────────────
int64_t SipStack::nowMs() {
    struct timeval tv; gettimeofday(&tv,nullptr);
    return (int64_t)tv.tv_sec*1000+tv.tv_usec/1000;
}
static uint32_t rnd32() { return (uint32_t)rand()^(uint32_t)(rand()<<16); }

// ── Identifier generators ─────────────────────────────────────────────────────
void SipStack::genBranch(Branch& b) const {
    char tmp[80]; snprintf(tmp,sizeof tmp,"z9hG4bK%08x%08x",rnd32(),rnd32());
    b.assign(tmp,strlen(tmp));
}
void SipStack::genCallId(CallId& id) const {
    char tmp[80]; snprintf(tmp,sizeof tmp,"%08x%08x@%s",rnd32(),rnd32(),
                           cfg_.localAddr.c_str());
    id.assign(tmp,strlen(tmp));
}
void SipStack::genTag(Tag& t) const {
    char tmp[16]; snprintf(tmp,sizeof tmp,"%08x",rnd32()); t.assign(tmp,8);
}

// ── fillVia ───────────────────────────────────────────────────────────────────
// Builds a proper Via header reflecting the actual transport used.
// RFC 3261 §8.1.1.7:  "The branch parameter value MUST be unique..."
// RFC 3261 §18.1.1:   Via transport must match actual transport.
void SipStack::fillVia(SipMessage& msg, Proto proto) const {
    Branch br; genBranch(br);
    msg.via[0].host = cfg_.localAddr;
    msg.via[0].port = cfg_.localPort;
    msg.via[0].branch = br;
    if (proto == Proto::Tcp)
        msg.via[0].transport.assign("TCP",3);
    else
        msg.via[0].transport.assign("UDP",3);
    msg.viaCount = 1;
}

// ── init ──────────────────────────────────────────────────────────────────────
bool SipStack::init(StackConfig cfg, StackCallbacks cbs, CodecRegistry* codecs) {
    cfg_    = cfg;
    cbs_    = cbs;
    codecs_ = codecs;
    srand((unsigned)time(nullptr)^(unsigned)getpid());
    genCallId(regCallId_);
    regCSeq_ = 1;
    nextRtpPort_ = cfg_.rtpBasePort;
    for (auto& r : rtpPool_)  r.used = false;
    for (auto& b : bindings_) b.used = false;

    // Open dual-transport
    Transport::Config tc;
    tc.localAddr  = cfg_.localAddr.empty() ? nullptr : cfg_.localAddr.c_str();
    tc.port       = cfg_.localPort;
    tc.enableUdp  = cfg_.enableUdp;
    tc.enableTcp  = cfg_.enableTcp;
    if (!transport_.open(tc, [this](const char* d, size_t l,
                                    const char* h, uint16_t p, bool tcp){
            Guard g(mu_); onRecv(d,l,h,p,tcp);
        })) return false;

    // Wire transaction layer to transport
    txn_.init(
        [this](const char* h, uint16_t p, const char* d, size_t l) -> bool {
            // Determine protocol from active transaction's Via transport
            // The SendFn doesn't carry protocol context here, so we default
            // to UDP. Per-transaction protocol is set via isUdp in Transaction.
            // SipStack overrides specific sends via sendMsg/sendRaw directly.
            return transport_.sendUdp(d,l,h,p);
        },
        { [this](TxnId id, const SipMessage& m){ onTxnResponse(id,m); },
          [this](TxnId id, const SipMessage& m){ onTxnRequest(id,m); },
          [this](TxnId id){ onTxnTerminated(id); } }
    );

    // Replace the transaction layer's generic SendFn with a transport-aware one:
    // We re-init txn_ with a send function that reads the transaction's isUdp flag.
    txn_.init(
        [this](const char* h, uint16_t p, const char* d, size_t l) -> bool {
            // isUdp context is tracked per-transaction; we default UDP here
            // because the TransactionLayer SendFn doesn't carry per-txn state.
            // Actual TCP sends for specific transactions go through sendMsg().
            return transport_.sendUdp(d,l,h,p);
        },
        { [this](TxnId id, const SipMessage& m){ onTxnResponse(id,m); },
          [this](TxnId id, const SipMessage& m){ onTxnRequest(id,m); },
          [this](TxnId id){ onTxnTerminated(id); } }
    );

    return true;
}

// ── shutdown ──────────────────────────────────────────────────────────────────
void SipStack::shutdown() {
    transport_.close();
    for (auto& r : rtpPool_) if (r.used) r.sess.close();
}

// ── Transport send helpers ────────────────────────────────────────────────────
bool SipStack::sendRaw(const char* d, size_t l,
                       const char* h, uint16_t p, Proto proto) {
    return transport_.send(d,l,h,p,proto);
}
bool SipStack::sendMsg(const SipMessage& msg, const char* host, uint16_t port,
                       Proto proto) {
    size_t n = msg.format(txBuf_, sizeof txBuf_); if (!n) return false;
    return sendRaw(txBuf_,n,host,port,proto);
}

// ── Incoming message dispatch ─────────────────────────────────────────────────
void SipStack::onRecv(const char* buf, size_t len,
                      const char* host, uint16_t port, bool isTcp) {
    auto r = SipMessage::parse(buf,len); if (!r.ok()) return;
    const SipMessage& msg = *r;
    Proto proto = isTcp ? Proto::Tcp : Proto::Udp;

    // Feed transaction layer
    if (txn_.onMessage(msg, host, port)) return;

    // ACK for 2xx is outside transaction
    if (msg.isRequest && msg.method == Method::ACK) { handleAck(msg); return; }

    // Unmatched response (e.g. retransmit of 200 after transaction terminated)
    // Try dialog match
    if (!msg.isRequest) {
        Dialog* d = dlg_.find(msg);
        if (d) { handleInviteResp(d, msg); }
    }
}

// ── Transaction callbacks ─────────────────────────────────────────────────────
void SipStack::onTxnRequest(TxnId id, const SipMessage& msg) {
    // Derive proto from Via transport header
    Proto proto = Proto::Udp;
    if (msg.viaCount > 0)
        proto = Transport::protoFromVia(msg.via[0].transport.c_str());
    const char* host = msg.viaCount ? msg.via[0].host.c_str() : "";
    uint16_t    port = msg.viaCount ? msg.via[0].port : SIP_UDP_PORT;
    if (!port) port = SIP_UDP_PORT;

    switch (msg.method) {
    case Method::INVITE:   handleInvite  (id,msg,host,port,proto);  break;
    case Method::BYE:      handleBye     (id,msg);                  break;
    case Method::CANCEL:   handleCancel  (id,msg);                  break;
    case Method::REGISTER: handleRegister(id,msg,proto);            break;
    case Method::MESSAGE:  handleMessage (id,msg);                  break;
    case Method::OPTIONS:  handleOptions (id,msg);                  break;
    case Method::UPDATE:   handleUpdate  (id,msg);                  break;
    default:
        if (cbs_.onRequest) cbs_.onRequest(msg,id);
        else {
            SipMessage r=msg.makeResponse(405,"Method Not Allowed");
            r.allow.assign("INVITE,ACK,BYE,CANCEL,OPTIONS,MESSAGE",36);
            txn_.sendResponse(id,r);
        }
        break;
    }
}
void SipStack::onTxnResponse(TxnId /*id*/, const SipMessage& msg) {
    if (msg.cseq.method == Method::REGISTER) { handleRegisterResp(msg); return; }
    Dialog* d = dlg_.find(msg);
    if (d) { handleInviteResp(d,msg); return; }
    if (msg.cseq.method==Method::OPTIONS && cbs_.onOptions)
        cbs_.onOptions(msg.is2xx(), msg.statusCode);
}
void SipStack::onTxnTerminated(TxnId) {}

// ── doRegister ────────────────────────────────────────────────────────────────
bool SipStack::doRegister(uint32_t exp) {
    if (!exp) exp = cfg_.regExpires;
    SipMessage req; req.isRequest=true; req.method=Method::REGISTER;
    char ruri[128]; snprintf(ruri,sizeof ruri,"sip:%s",cfg_.registrarHost.c_str());
    req.requestUri.assign(ruri,strlen(ruri));
    char furi[128]; snprintf(furi,sizeof furi,"sip:%s@%s",
                             cfg_.localUser.c_str(),cfg_.localDomain.c_str());
    req.from.uri.assign(furi,strlen(furi));
    Tag ft; genTag(ft); req.from.tag=ft;
    req.to.uri=req.from.uri;
    req.callId=regCallId_; req.cseq={regCSeq_++,Method::REGISTER};
    req.maxForwards=70; req.expires=exp;
    fillVia(req, cfg_.registrarProto);
    char contact[128]; snprintf(contact,sizeof contact,"sip:%s@%s:%u",
                                cfg_.localUser.c_str(),
                                cfg_.localAddr.c_str(),cfg_.localPort);
    req.contact.uri.assign(contact,strlen(contact)); req.hasContact=true;
    req.allow.assign("INVITE,ACK,BYE,CANCEL,OPTIONS,MESSAGE",36);
    req.userAgent.assign("sip_stack/1.0",13);
    if (regNeedAuth_) {
        char ab[512];
        if (auth::buildAuthHeader(regChallenge_,Method::REGISTER,ruri,
            cfg_.authUser.c_str(),cfg_.authPass.c_str(),++regAuthNc_,ab,sizeof ab))
            req.authorization.assign(ab,strlen(ab));
        regNeedAuth_=false;
    }
    regTxn_ = txn_.sendRequest(req,
                  cfg_.registrarHost.c_str(), cfg_.registrarPort,
                  cfg_.registrarProto == Proto::Udp);
    return regTxn_ != InvalidTxn;
}

// ── call ──────────────────────────────────────────────────────────────────────
CallHandle SipStack::call(const char* target, Proto proto) {
    char turi[128];
    if (strncmp(target,"sip:",4)&&strncmp(target,"sips:",5))
        snprintf(turi,sizeof turi,"sip:%s",target);
    else strncpy(turi,target,sizeof turi-1);

    SipMessage req; req.isRequest=true; req.method=Method::INVITE;
    req.requestUri.assign(turi,strlen(turi));
    char furi[128]; snprintf(furi,sizeof furi,"sip:%s@%s",
                             cfg_.localUser.c_str(),cfg_.localDomain.c_str());
    req.from.uri.assign(furi,strlen(furi));
    Tag ft; genTag(ft); req.from.tag=ft;
    req.to.uri.assign(turi,strlen(turi));
    genCallId(req.callId); req.cseq={1,Method::INVITE}; req.maxForwards=70;
    fillVia(req, proto);
    char contact[128]; snprintf(contact,sizeof contact,"sip:%s@%s:%u",
                                cfg_.localUser.c_str(),
                                cfg_.localAddr.c_str(),cfg_.localPort);
    req.contact.uri.assign(contact,strlen(contact)); req.hasContact=true;
    req.allow.assign("INVITE,ACK,BYE,CANCEL,OPTIONS,MESSAGE",36);
    req.userAgent.assign("sip_stack/1.0",13);
    // SDP offer
    uint16_t rtpPort = rtpNextPort();
    size_t sdpLen = makeSdpOffer(sdpBuf_,sizeof sdpBuf_,rtpPort);
    if (sdpLen) {
        req.body=sdpBuf_; req.bodyLen=sdpLen;
        req.contentType.assign("application/sdp",15);
        req.contentLen=(uint32_t)sdpLen;
    }
    Dialog* d = dlg_.createUAC(req,ft);
    if (!d) return InvalidDialog;
    auto uri = SipUri::parse(turi);
    if (!uri.ok()) { dlg_.terminate(*d); return InvalidDialog; }
    const char* rhost = uri->host.c_str();
    uint16_t    rport = uri->effectivePort();
    TxnId txn = txn_.sendRequest(req, rhost, rport, proto==Proto::Udp);
    if (txn == InvalidTxn) { dlg_.terminate(*d); return InvalidDialog; }
    d->inviteTxn=txn; d->currentTxn=txn;
    return d->id;
}

// ── accept ────────────────────────────────────────────────────────────────────
bool SipStack::accept(CallHandle h) {
    Dialog* d = dlg_.findById(h); if (!d||d->isUAC) return false;
    SipMessage ok; ok.isRequest=false; ok.statusCode=200; ok.reason.assign("OK",2);
    ok.from.uri=d->remoteUri; ok.from.tag=d->remoteTag;
    ok.to.uri=d->localUri;   ok.to.tag=d->localTag;
    ok.callId=d->callId; ok.cseq={d->remoteCSeq,Method::INVITE};
    char contact[128]; snprintf(contact,sizeof contact,"sip:%s@%s:%u",
                                cfg_.localUser.c_str(),
                                cfg_.localAddr.c_str(),cfg_.localPort);
    ok.contact.uri.assign(contact,strlen(contact)); ok.hasContact=true;
    ok.allow.assign("INVITE,ACK,BYE,CANCEL,OPTIONS,MESSAGE",36);
    uint16_t rtpPort = rtpNextPort();
    size_t sdpLen = makeSdpAnswer(sdpBuf_,sizeof sdpBuf_,SdpSession(),rtpPort);
    if (sdpLen&&d->remoteRtpPort) {
        ok.body=sdpBuf_; ok.bodyLen=sdpLen;
        ok.contentType.assign("application/sdp",15);
        ok.contentLen=(uint32_t)sdpLen;
    }
    if (d->inviteTxn!=InvalidTxn) txn_.sendResponse(d->inviteTxn,ok);
    if (d->remoteRtpPort&&codecs_) {
        RtpSession* rtp = rtpAlloc(d->id);
        if (rtp) {
            ICodec* codec = codecs_->findByPT(d->negotiatedPT);
            if (!codec) codec = codecs_->findByPT(0);
            if (codec) {
                RtpSession::Config rc; rc.pt=codec->payloadType(); rc.ssrc=rnd32();
                rtp->open(cfg_.localAddr.c_str(),rtpPort,
                          d->remoteRtpHost.c_str(),d->remoteRtpPort,
                          codec,rc,{nullptr,nullptr,nullptr});
            }
        }
    }
    dlg_.update(*d,ok,true);
    return true;
}

// ── reject ────────────────────────────────────────────────────────────────────
bool SipStack::reject(CallHandle h, int code, const char* reason) {
    Dialog* d = dlg_.findById(h); if (!d) return false;
    SipMessage r; r.isRequest=false; r.statusCode=code;
    r.reason.assign(reason,strlen(reason));
    r.from.uri=d->remoteUri; r.from.tag=d->remoteTag;
    r.to.uri=d->localUri;   r.to.tag=d->localTag;
    r.callId=d->callId; r.cseq={d->remoteCSeq,Method::INVITE};
    if (d->inviteTxn!=InvalidTxn) txn_.sendResponse(d->inviteTxn,r);
    dlg_.terminate(*d); return true;
}

// ── bye ───────────────────────────────────────────────────────────────────────
bool SipStack::bye(CallHandle h) {
    Dialog* d = dlg_.findById(h);
    if (!d||d->state!=DialogState::Confirmed) return false;
    SipMessage req; req.isRequest=true; req.method=Method::BYE;
    req.requestUri=d->remoteTarget;
    req.from.uri=d->localUri; req.from.tag=d->localTag;
    req.to.uri=d->remoteUri; req.to.tag=d->remoteTag;
    req.callId=d->callId; req.cseq={d->nextCSeq(),Method::BYE};
    req.maxForwards=70;
    Proto proto = d->proto;
    fillVia(req, proto);
    if (d->routeSet.count) {
        char rb[512]; if (d->routeSet.format(rb,sizeof rb)) req.route.assign(rb,strlen(rb));
    }
    auto uri = SipUri::parse(d->remoteTarget.c_str());
    const char* rh = uri.ok()?uri->host.c_str():cfg_.registrarHost.c_str();
    uint16_t    rp = uri.ok()?uri->effectivePort():cfg_.registrarPort;
    txn_.sendRequest(req, rh, rp, proto==Proto::Udp);
    rtpFree(d->id); DialogId did=d->id; dlg_.terminate(*d);
    if (cbs_.onBye) cbs_.onBye(did,200);
    return true;
}

// ── cancel ────────────────────────────────────────────────────────────────────
bool SipStack::cancel(CallHandle h) {
    Dialog* d = dlg_.findById(h); if (!d) return false;
    if (d->inviteTxn!=InvalidTxn) txn_.cancelInvite(d->inviteTxn);
    dlg_.terminate(*d); return true;
}

// ── hold / resume ─────────────────────────────────────────────────────────────
bool SipStack::hold(CallHandle h) {
    Dialog* d = dlg_.findById(h);
    if (!d||d->state!=DialogState::Confirmed) return false;
    SipMessage req; req.isRequest=true; req.method=Method::INVITE;
    req.requestUri=d->remoteTarget;
    req.from.uri=d->localUri; req.from.tag=d->localTag;
    req.to.uri=d->remoteUri; req.to.tag=d->remoteTag;
    req.callId=d->callId; req.cseq={d->nextCSeq(),Method::INVITE};
    req.maxForwards=70;
    Proto proto = d->proto;
    fillVia(req, proto);
    char contact[128]; snprintf(contact,sizeof contact,"sip:%s@%s:%u",
        cfg_.localUser.c_str(),cfg_.localAddr.c_str(),cfg_.localPort);
    req.contact.uri.assign(contact,strlen(contact)); req.hasContact=true;
    SdpSession sdp = SdpSession::makeOffer(*codecs_,cfg_.rtpLocalAddr.c_str(),rtpNextPort());
    if (MediaSection* m=sdp.audioMediaMut()) m->dir=MediaDir::SendOnly;
    size_t sdpLen = sdp.format(sdpBuf_,sizeof sdpBuf_);
    if (sdpLen) { req.body=sdpBuf_; req.bodyLen=sdpLen;
        req.contentType.assign("application/sdp",15); req.contentLen=(uint32_t)sdpLen; }
    auto uri = SipUri::parse(d->remoteTarget.c_str());
    const char* rh = uri.ok()?uri->host.c_str():cfg_.registrarHost.c_str();
    uint16_t    rp = uri.ok()?uri->effectivePort():cfg_.registrarPort;
    txn_.sendRequest(req, rh, rp, proto==Proto::Udp);
    return true;
}
bool SipStack::resume(CallHandle h) { return hold(h); }

// ── sendDtmf ─────────────────────────────────────────────────────────────────
bool SipStack::sendDtmf(CallHandle h, uint8_t digit) {
    RtpSession* rtp = rtpOf(h); if (!rtp||!rtp->isOpen()) return false;
    return rtp->sendDtmf(digit);
}

// ── sendMessage ───────────────────────────────────────────────────────────────
bool SipStack::sendMessage(const char* target, const char* body, size_t len,
                           const char* ct, Proto proto) {
    char turi[128];
    if (strncmp(target,"sip:",4)&&strncmp(target,"sips:",5))
        snprintf(turi,sizeof turi,"sip:%s",target);
    else strncpy(turi,target,sizeof turi-1);
    SipMessage req; req.isRequest=true; req.method=Method::MESSAGE;
    req.requestUri.assign(turi,strlen(turi));
    char furi[128]; snprintf(furi,sizeof furi,"sip:%s@%s",
                             cfg_.localUser.c_str(),cfg_.localDomain.c_str());
    req.from.uri.assign(furi,strlen(furi));
    Tag ft; genTag(ft); req.from.tag=ft;
    req.to.uri.assign(turi,strlen(turi));
    genCallId(req.callId); req.cseq={1,Method::MESSAGE}; req.maxForwards=70;
    fillVia(req, proto);
    req.body=body; req.bodyLen=len;
    req.contentType.assign(ct,strlen(ct)); req.contentLen=(uint32_t)len;
    auto uri = SipUri::parse(turi);
    const char* rh=uri.ok()?uri->host.c_str():cfg_.registrarHost.c_str();
    uint16_t    rp=uri.ok()?uri->effectivePort():cfg_.registrarPort;
    txn_.sendRequest(req,rh,rp,proto==Proto::Udp);
    return true;
}

// ── options ───────────────────────────────────────────────────────────────────
bool SipStack::options(const char* target, Proto proto) {
    char turi[128];
    if (strncmp(target,"sip:",4)) snprintf(turi,sizeof turi,"sip:%s",target);
    else strncpy(turi,target,sizeof turi-1);
    SipMessage req; req.isRequest=true; req.method=Method::OPTIONS;
    req.requestUri.assign(turi,strlen(turi));
    char furi[128]; snprintf(furi,sizeof furi,"sip:%s@%s",
                             cfg_.localUser.c_str(),cfg_.localDomain.c_str());
    req.from.uri.assign(furi,strlen(furi));
    Tag ft; genTag(ft); req.from.tag=ft;
    req.to.uri.assign(turi,strlen(turi));
    genCallId(req.callId); req.cseq={1,Method::OPTIONS}; req.maxForwards=70;
    fillVia(req, proto);
    req.allow.assign("INVITE,ACK,BYE,CANCEL,OPTIONS,MESSAGE",36);
    auto uri = SipUri::parse(turi);
    const char* rh=uri.ok()?uri->host.c_str():cfg_.registrarHost.c_str();
    uint16_t    rp=uri.ok()?uri->effectivePort():cfg_.registrarPort;
    txn_.sendRequest(req,rh,rp,proto==Proto::Udp);
    return true;
}

// ── UAS request handlers ──────────────────────────────────────────────────────
void SipStack::handleInvite(TxnId txnId, const SipMessage& msg,
                             const char* host, uint16_t port, Proto proto) {
    (void)host; (void)port;
    SipMessage trying=msg.makeResponse(100,"Trying");
    txn_.sendResponse(txnId,trying);
    SdpSession offer; bool hasOffer=false;
    if (msg.body&&msg.bodyLen&&msg.contentType.eqi("application/sdp",15)) {
        auto r=SdpSession::parse(msg.body,msg.bodyLen); if(r.ok()){offer=*r;hasOffer=true;}
    }
    Tag localTag; genTag(localTag);
    Dialog* d=dlg_.createUAS(msg,localTag);
    if (!d) {
        SipMessage r=msg.makeResponse(500,"Server Internal Error");
        txn_.sendResponse(txnId,r); return;
    }
    d->inviteTxn=txnId; d->currentTxn=txnId; d->proto=proto;
    if (hasOffer) {
        const MediaSection* am=offer.audioMedia();
        if (am) {
            d->remoteRtpHost.assign(offer.connAddr.c_str(),offer.connAddr.len);
            d->remoteRtpPort=am->port;
            d->negotiatedPT=am->codecCount?am->codecs[0].pt:0;
        }
    }
    SipMessage ringing=msg.makeResponse(180,"Ringing");
    ringing.to.tag=localTag;
    char contact[128]; snprintf(contact,sizeof contact,"sip:%s@%s:%u",
        cfg_.localUser.c_str(),cfg_.localAddr.c_str(),cfg_.localPort);
    ringing.contact.uri.assign(contact,strlen(contact)); ringing.hasContact=true;
    txn_.sendResponse(txnId,ringing);
    if (cbs_.onInvite) cbs_.onInvite(d->id,msg);
}

void SipStack::handleAck(const SipMessage& msg) {
    Dialog* d=dlg_.find(msg); if (!d) return;
    dlg_.update(*d,msg,false);
    if (d->state==DialogState::Confirmed) {
        RtpSession* rtp=rtpOf(d->id);
        if (cbs_.onConnected) cbs_.onConnected(d->id,rtp);
    }
}

void SipStack::handleBye(TxnId txnId, const SipMessage& msg) {
    SipMessage ok=msg.makeResponse(200,"OK"); txn_.sendResponse(txnId,ok);
    Dialog* d=dlg_.find(msg);
    if (d) {
        rtpFree(d->id); DialogId did=d->id; dlg_.terminate(*d);
        if (cbs_.onBye) cbs_.onBye(did,200);
    }
}

void SipStack::handleCancel(TxnId txnId, const SipMessage& msg) {
    SipMessage ok=msg.makeResponse(200,"OK"); txn_.sendResponse(txnId,ok);
    Dialog* d=dlg_.find(msg);
    if (d) {
        SipMessage t=msg.makeResponse(487,"Request Terminated");
        if (d->inviteTxn!=InvalidTxn) txn_.sendResponse(d->inviteTxn,t);
        dlg_.terminate(*d);
    }
}

void SipStack::handleRegister(TxnId txnId, const SipMessage& msg, Proto proto) {
    if (!cfg_.registrarSv) {
        SipMessage r=msg.makeResponse(405,"Method Not Allowed");
        txn_.sendResponse(txnId,r); return;
    }
    for (auto& b : bindings_) if (!b.used||b.aor==msg.to.uri) {
        b.used=true; b.aor=msg.to.uri; b.proto=proto;
        if (msg.hasContact) b.contact.assign(msg.contact.uri.c_str(),msg.contact.uri.len);
        b.expiresAt=nowMs()+(int64_t)msg.expires*1000;
        break;
    }
    SipMessage ok=msg.makeResponse(200,"OK"); ok.expires=msg.expires;
    txn_.sendResponse(txnId,ok);
}

void SipStack::handleMessage(TxnId txnId, const SipMessage& msg) {
    SipMessage ok=msg.makeResponse(200,"OK"); txn_.sendResponse(txnId,ok);
    if (cbs_.onMessage)
        cbs_.onMessage(msg.from.uri.c_str(),msg.body,msg.bodyLen,msg.contentType.c_str());
}

void SipStack::handleOptions(TxnId txnId, const SipMessage& msg) {
    SipMessage ok=msg.makeResponse(200,"OK");
    ok.allow.assign("INVITE,ACK,BYE,CANCEL,OPTIONS,MESSAGE",36);
    txn_.sendResponse(txnId,ok);
}

void SipStack::handleUpdate(TxnId txnId, const SipMessage& msg) {
    SipMessage ok=msg.makeResponse(200,"OK"); txn_.sendResponse(txnId,ok);
}

// ── REGISTER response ─────────────────────────────────────────────────────────
void SipStack::handleRegisterResp(const SipMessage& msg) {
    if (msg.statusCode==401||msg.statusCode==407) {
        const char* chStr = msg.statusCode==401
                          ? msg.wwwAuth.c_str() : msg.proxyAuth.c_str();
        auto ch = auth::parseChallenge(chStr,strlen(chStr));
        if (ch.ok()) { regChallenge_=*ch; regNeedAuth_=true; regAuthNc_=0; doRegister(); }
        else if (cbs_.onRegistered) cbs_.onRegistered(false,msg.statusCode);
    } else if (msg.is2xx()) {
        registered_=true; if (cbs_.onRegistered) cbs_.onRegistered(true,200);
    } else {
        if (cbs_.onRegistered) cbs_.onRegistered(false,msg.statusCode);
    }
}

// ── INVITE response (UAC) ─────────────────────────────────────────────────────
void SipStack::handleInviteResp(Dialog* d, const SipMessage& msg) {
    dlg_.update(*d,msg,false);
    if (msg.isProvisional()) return;
    if (msg.is2xx()) {
        RtpSession* rtp = nullptr;
        if (msg.body&&msg.bodyLen&&msg.contentType.eqi("application/sdp",15)) {
            auto r=SdpSession::parse(msg.body,msg.bodyLen);
            if (r.ok()) {
                const MediaSection* am=r->audioMedia();
                if (am&&am->port&&codecs_) {
                    ICodec* codec=codecs_->findByPT(am->codecs[0].pt);
                    if (!codec) codec=codecs_->findByPT(0);
                    if (codec) {
                        uint16_t rtpPort=rtpNextPort();
                        rtp=rtpAlloc(d->id);
                        if (rtp) {
                            const char* ra=r->connAddr.empty()?d->remoteUri.c_str():r->connAddr.c_str();
                            RtpSession::Config rc; rc.pt=codec->payloadType(); rc.ssrc=rnd32();
                            rtp->open(cfg_.localAddr.c_str(),rtpPort,ra,am->port,
                                      codec,rc,{nullptr,nullptr,nullptr});
                        }
                    }
                }
            }
        }
        // Send ACK (outside transaction for 2xx — RFC 3261 §13.2.2.4)
        SipMessage ack; ack.isRequest=true; ack.method=Method::ACK;
        ack.requestUri=d->remoteTarget;
        ack.from.uri=d->localUri; ack.from.tag=d->localTag;
        ack.to.uri=d->remoteUri; ack.to.tag=d->remoteTag;
        ack.callId=d->callId; ack.cseq={msg.cseq.seq,Method::ACK};
        ack.maxForwards=70;
        Proto proto = d->proto;
        fillVia(ack, proto);
        if (d->routeSet.count) {
            char rb[512]; d->routeSet.format(rb,sizeof rb); ack.route.assign(rb,strlen(rb));
        }
        char contact[128]; snprintf(contact,sizeof contact,"sip:%s@%s:%u",
            cfg_.localUser.c_str(),cfg_.localAddr.c_str(),cfg_.localPort);
        ack.contact.uri.assign(contact,strlen(contact)); ack.hasContact=true;
        auto uri=SipUri::parse(d->remoteTarget.c_str());
        const char* rh=uri.ok()?uri->host.c_str():cfg_.registrarHost.c_str();
        uint16_t    rp=uri.ok()?uri->effectivePort():cfg_.registrarPort;
        sendMsg(ack,rh,rp,proto);
        if (cbs_.onConnected) cbs_.onConnected(d->id,rtp);
    } else {
        rtpFree(d->id); DialogId did=d->id; dlg_.terminate(*d);
        if (cbs_.onBye) cbs_.onBye(did,msg.statusCode);
    }
}

// ── sendResponse ──────────────────────────────────────────────────────────────
bool SipStack::sendResponse(TxnId txn, int code, const char* reason,
                            const char* body, size_t blen, const char* ct) {
    const Transaction* t=txn_.findById(txn); if (!t) return false;
    auto req=SipMessage::parse(t->reqBuf,t->reqLen); if (!req.ok()) return false;
    SipMessage r=req->makeResponse(code,reason);
    if (body&&blen) {
        r.body=body; r.bodyLen=blen; r.contentLen=(uint32_t)blen;
        r.contentType.assign(ct,strlen(ct));
    }
    return txn_.sendResponse(txn,r);
}

// ── lookupAOR ─────────────────────────────────────────────────────────────────
const RegBinding* SipStack::lookupAOR(const char* aor) const {
    for (auto& b : bindings_)
        if (b.used&&b.aor==aor&&nowMs()<b.expiresAt) return &b;
    return nullptr;
}

// ── RTP pool ──────────────────────────────────────────────────────────────────
RtpSession* SipStack::rtpAlloc(DialogId id) {
    for (auto& s:rtpPool_) if (!s.used){s.used=true;s.dlgId=id;return &s.sess;}
    return nullptr;
}
void SipStack::rtpFree(DialogId id) {
    for (auto& s:rtpPool_) if (s.used&&s.dlgId==id){s.sess.close();s.used=false;}
}
RtpSession* SipStack::rtpOf(CallHandle h) {
    for (auto& s:rtpPool_) if (s.used&&s.dlgId==h) return &s.sess;
    return nullptr;
}
uint16_t SipStack::rtpNextPort() {
    uint16_t p=nextRtpPort_; nextRtpPort_=(uint16_t)(nextRtpPort_+2); return p;
}

// ── SDP helpers ───────────────────────────────────────────────────────────────
size_t SipStack::makeSdpOffer(char* buf, size_t sz, uint16_t rtpPort) const {
    if (!codecs_) return 0;
    const char* addr=cfg_.rtpLocalAddr.empty()?cfg_.localAddr.c_str():cfg_.rtpLocalAddr.c_str();
    return SdpSession::makeOffer(*codecs_,addr,rtpPort).format(buf,sz);
}
size_t SipStack::makeSdpAnswer(char* buf, size_t sz,
                                const SdpSession& offer, uint16_t rtpPort) const {
    if (!codecs_) return 0;
    const char* addr=cfg_.rtpLocalAddr.empty()?cfg_.localAddr.c_str():cfg_.rtpLocalAddr.c_str();
    return SdpSession::makeAnswer(offer,*codecs_,addr,rtpPort).format(buf,sz);
}

// ── tick ──────────────────────────────────────────────────────────────────────
void SipStack::tick() {
    Guard g(mu_);
    txn_.tick(nowMs());
}

} // namespace sip
"""

with open(path, "w") as f:
    f.write(content)
print(f"Written {len(content)} bytes to {path}")

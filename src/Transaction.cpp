// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

// Transaction.cpp – RFC 3261 §17 FSMs: ICT, NICT, IST, NIST
#include "Transaction.h"
#include <cstring>
#include <cstdio>
#include <sys/time.h>
#include <algorithm>

namespace sip {

void TransactionLayer::init(SendFn s, TxnCallbacks c) { send_=s; cbs_=c; }

Transaction* TransactionLayer::findByKey(const Branch& br, Method m, TxnRole role) const {
    return const_cast<Pool<Transaction,SIP_MAX_TXNS>&>(pool_).find(
        [&](Transaction& t){ return t.role==role && t.branch==br && t.method==m; });
}
Transaction* TransactionLayer::findByIdM(TxnId id) {
    return pool_.find([&](Transaction& t){ return t.id==id; });
}
const Transaction* TransactionLayer::findById(TxnId id) const {
    return const_cast<TransactionLayer*>(this)->findByIdM(id);
}

static int64_t ms() { struct timeval tv; gettimeofday(&tv,nullptr); return (int64_t)tv.tv_sec*1000+tv.tv_usec/1000; }

void TransactionLayer::transmit(Transaction& t)     { if(t.reqLen)  send_(t.remoteHost.c_str(),t.remotePort,t.reqBuf, t.reqLen);  }
void TransactionLayer::transmitResp(Transaction& t) { if(t.respLen) send_(t.remoteHost.c_str(),t.remotePort,t.respBuf,t.respLen); }

void TransactionLayer::terminate(Transaction& t) {
    if(cbs_.onTerminated) cbs_.onTerminated(t.id);
    pool_.release(&t);
}

TxnId TransactionLayer::sendRequest(const SipMessage& req, const char* host, uint16_t port, bool udp) {
    Transaction* t=pool_.alloc(); if(!t) return InvalidTxn;
    t->id=nextId_++; t->role=TxnRole::Client;
    t->type=(req.method==Method::INVITE)?TxnType::Invite:TxnType::NonInvite;
    t->method=req.method; t->cseq=req.cseq.seq;
    t->branch=req.via[0].branch; t->callId=req.callId;
    t->remoteHost.assign(host,strlen(host)); t->remotePort=port; t->isUdp=udp;
    t->reqLen=req.format(t->reqBuf,sizeof t->reqBuf);
    int64_t now=ms();
    if(t->type==TxnType::Invite) {
        t->state=TxnState::ICT_Calling;
        t->timerA=udp?now+SIP_T1:0; t->timerB=now+64*SIP_T1;
        t->retransmitInterval=SIP_T1;
    } else {
        t->state=TxnState::NICT_Trying;
        t->timerE=udp?now+SIP_T1:0; t->timerF=now+64*SIP_T1;
        t->retransmitInterval=SIP_T1;
    }
    transmit(*t); return t->id;
}

bool TransactionLayer::sendResponse(TxnId id, const SipMessage& resp) {
    Transaction* t=findByIdM(id); if(!t) return false;
    t->respLen=resp.format(t->respBuf,sizeof t->respBuf);
    transmitResp(*t);
    int64_t now=ms();
    if(t->type==TxnType::Invite) {
        if(resp.isProvisional())  t->state=TxnState::IST_Proceeding;
        else if(resp.is2xx())     { terminate(*t); return true; }
        else { t->state=TxnState::IST_Completed; t->timerG=t->isUdp?now+SIP_T1:0; t->timerH=now+64*SIP_T1; }
    } else {
        if(resp.isProvisional())  t->state=TxnState::NIST_Proceeding;
        else { t->state=TxnState::NIST_Completed; t->timerJ=t->isUdp?now+64*SIP_T1:now+1; }
    }
    return true;
}

bool TransactionLayer::cancelInvite(TxnId id) {
    Transaction* t=findByIdM(id);
    if(!t||t->type!=TxnType::Invite||t->role!=TxnRole::Client) return false;
    auto inv=SipMessage::parse(t->reqBuf,t->reqLen); if(!inv.ok()) return false;
    SipMessage c; c.isRequest=true; c.method=Method::CANCEL;
    c.requestUri=inv->requestUri; c.from=inv->from; c.to=inv->to;
    c.callId=inv->callId; c.cseq={inv->cseq.seq,Method::CANCEL};
    c.maxForwards=70; c.via[0]=inv->via[0]; c.viaCount=1;
    sendRequest(c,t->remoteHost.c_str(),t->remotePort,t->isUdp);
    return true;
}

bool TransactionLayer::onMessage(const SipMessage& msg, const char* srcHost, uint16_t srcPort) {
    if(msg.isRequest) {
        if(msg.viaCount==0) return false;
        const Branch& br=msg.via[0].branch;
        if(msg.method==Method::CANCEL) {
            Transaction* inv=findByKey(br,Method::INVITE,TxnRole::Server);
            if(inv){ feedIST(*inv,msg); return true; }
        }
        // ACK for non-2xx goes to INVITE server transaction
        if(msg.method==Method::ACK) {
            Transaction* inv=findByKey(br,Method::INVITE,TxnRole::Server);
            if(inv){ feedIST(*inv,msg); return true; }
        }
        Transaction* t=findByKey(br,msg.method,TxnRole::Server);
        if(t){ if(t->respLen) transmitResp(*t); return true; }
        // New server transaction
        t=pool_.alloc(); if(!t) return false;
        t->id=nextId_++; t->role=TxnRole::Server;
        t->type=(msg.method==Method::INVITE)?TxnType::Invite:TxnType::NonInvite;
        t->method=msg.method; t->cseq=msg.cseq.seq; t->branch=br; t->callId=msg.callId;
        t->remoteHost.assign(srcHost,strlen(srcHost)); t->remotePort=srcPort; t->isUdp=true;
        t->state=(t->type==TxnType::Invite)?TxnState::IST_Proceeding:TxnState::NIST_Trying;
        if(cbs_.onRequest) cbs_.onRequest(t->id,msg);
        return true;
    } else {
        if(msg.viaCount==0) return false;
        const Branch& br=msg.via[0].branch; Method m=msg.cseq.method;
        Transaction* t=findByKey(br,m,TxnRole::Client); if(!t) return false;
        if(t->type==TxnType::Invite) feedICT(*t,msg); else feedNICT(*t,msg);
        return true;
    }
}

void TransactionLayer::feedICT(Transaction& t, const SipMessage& msg) {
    if(t.state==TxnState::ICT_Calling||t.state==TxnState::ICT_Proceeding) {
        if(msg.isProvisional()) {
            t.state=TxnState::ICT_Proceeding; t.timerA=0;
            if(cbs_.onResponse) cbs_.onResponse(t.id,msg);
        } else if(msg.is2xx()) {
            t.timerA=t.timerB=0; if(cbs_.onResponse) cbs_.onResponse(t.id,msg); terminate(t);
        } else {
            t.state=TxnState::ICT_Completed;
            t.timerD=t.isUdp?ms()+32000:ms()+1; t.timerA=t.timerB=0;
            if(cbs_.onResponse) cbs_.onResponse(t.id,msg);
            // send ACK for 3xx-6xx
            auto orig=SipMessage::parse(t.reqBuf,t.reqLen);
            if(orig.ok()){ SipMessage ack; ack.isRequest=true; ack.method=Method::ACK;
                ack.requestUri=orig->requestUri; ack.from=orig->from; ack.to=msg.to;
                ack.callId=orig->callId; ack.cseq={orig->cseq.seq,Method::ACK};
                ack.maxForwards=70; ack.via[0]=orig->via[0]; ack.viaCount=1;
                char ab[SIP_MAX_MSG]; size_t al=ack.format(ab,sizeof ab);
                if(al) send_(t.remoteHost.c_str(),t.remotePort,ab,al); }
        }
    } else if(t.state==TxnState::ICT_Completed&&msg.isFinal()&&!msg.is2xx()) {
        // retransmit ACK
        auto orig=SipMessage::parse(t.reqBuf,t.reqLen);
        if(orig.ok()){ SipMessage ack; ack.isRequest=true; ack.method=Method::ACK;
            ack.requestUri=orig->requestUri; ack.from=orig->from; ack.to=msg.to;
            ack.callId=orig->callId; ack.cseq={orig->cseq.seq,Method::ACK};
            ack.maxForwards=70; ack.via[0]=orig->via[0]; ack.viaCount=1;
            char ab[SIP_MAX_MSG]; size_t al=ack.format(ab,sizeof ab);
            if(al) send_(t.remoteHost.c_str(),t.remotePort,ab,al); }
    }
}

void TransactionLayer::feedNICT(Transaction& t, const SipMessage& msg) {
    if(t.state==TxnState::NICT_Trying||t.state==TxnState::NICT_Proceeding) {
        if(msg.isProvisional()) {
            t.state=TxnState::NICT_Proceeding; t.timerE=0;
            if(cbs_.onResponse) cbs_.onResponse(t.id,msg);
        } else {
            t.timerE=t.timerF=0; t.state=TxnState::NICT_Completed;
            t.timerK=t.isUdp?ms()+SIP_T4:ms()+1;
            if(cbs_.onResponse) cbs_.onResponse(t.id,msg);
        }
    }
}

void TransactionLayer::feedIST(Transaction& t, const SipMessage& msg) {
    if(msg.method==Method::ACK&&t.state==TxnState::IST_Completed) {
        t.state=TxnState::IST_Confirmed; t.timerG=t.timerH=0;
        t.timerI=t.isUdp?ms()+SIP_T4:ms()+1;
    } else if(msg.method==Method::CANCEL&&t.state==TxnState::IST_Proceeding) {
        if(cbs_.onRequest) cbs_.onRequest(t.id,msg);
    }
}

void TransactionLayer::feedNIST(Transaction& t, const SipMessage& msg) { (void)t; (void)msg; }

void TransactionLayer::tick(int64_t now) {
    pool_.forEach([&](Transaction& t){
        switch(t.state) {
        case TxnState::ICT_Calling:
            if(t.timerB&&now>=t.timerB){terminate(t);return;}
            if(t.timerA&&now>=t.timerA){t.retransmitInterval=std::min(t.retransmitInterval*2,SIP_T2);t.timerA=now+t.retransmitInterval;transmit(t);}
            break;
        case TxnState::ICT_Completed:
            if(t.timerD&&now>=t.timerD) terminate(t); break;
        case TxnState::NICT_Trying: case TxnState::NICT_Proceeding:
            if(t.timerF&&now>=t.timerF){terminate(t);return;}
            if(t.timerE&&now>=t.timerE){t.retransmitInterval=std::min(t.retransmitInterval*2,SIP_T2);t.timerE=now+t.retransmitInterval;transmit(t);}
            break;
        case TxnState::NICT_Completed:
            if(t.timerK&&now>=t.timerK) terminate(t); break;
        case TxnState::IST_Completed:
            if(t.timerH&&now>=t.timerH){terminate(t);return;}
            if(t.timerG&&now>=t.timerG){t.retransmitInterval=std::min(t.retransmitInterval*2,SIP_T2);t.timerG=now+t.retransmitInterval;transmitResp(t);}
            break;
        case TxnState::IST_Confirmed:
            if(t.timerI&&now>=t.timerI) terminate(t); break;
        case TxnState::NIST_Completed:
            if(t.timerJ&&now>=t.timerJ) terminate(t); break;
        default: break;
        }
    });
}

} // namespace sip

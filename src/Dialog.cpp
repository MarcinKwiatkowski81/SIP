// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

// Dialog.cpp – SIP Dialog (RFC 3261 §12)
#include "Dialog.h"
#include <cstring>

namespace sip {

Dialog* DialogLayer::createUAC(const SipMessage& req, const Tag& localTag) {
    Dialog* d=pool_.alloc(); if(!d) return nullptr;
    d->id=nextId_++; d->state=DialogState::Null; d->isUAC=true;
    d->callId=req.callId; d->localTag=localTag;
    d->localCSeq=req.cseq.seq; d->remoteCSeq=0;
    d->localUri.assign(req.from.uri.c_str(),req.from.uri.len);
    d->remoteUri.assign(req.to.uri.c_str(),req.to.uri.len);
    d->remoteTarget=d->remoteUri; d->routeSet.clear();
    return d;
}

Dialog* DialogLayer::createUAS(const SipMessage& req, const Tag& localTag) {
    Dialog* d=pool_.alloc(); if(!d) return nullptr;
    d->id=nextId_++; d->state=DialogState::Null; d->isUAC=false;
    d->callId=req.callId; d->localTag=localTag; d->remoteTag=req.from.tag;
    d->localCSeq=0; d->remoteCSeq=req.cseq.seq;
    d->localUri.assign(req.to.uri.c_str(),req.to.uri.len);
    d->remoteUri.assign(req.from.uri.c_str(),req.from.uri.len);
    d->remoteTarget=(req.hasContact)?URI(req.contact.uri.c_str(),req.contact.uri.len):d->remoteUri;
    d->routeSet.clear();
    // Route set from Record-Route (UAS keeps forward order)
    if(!req.recordRoute.empty()) {
        const char* p=req.recordRoute.c_str(), *end=p+req.recordRoute.len;
        while(p<end) {
            while(p<end&&(*p==' '||*p==','))++p; if(p>=end) break;
            const char* lb=(const char*)memchr(p,'<',(size_t)(end-p)); if(!lb) break; ++lb;
            const char* rb=(const char*)memchr(lb,'>',(size_t)(end-lb)); if(!rb) break;
            d->routeSet.push(lb,(size_t)(rb-lb)); p=rb+1;
        }
    }
    return d;
}

bool Dialog::matches(const SipMessage& msg) const {
    if(state==DialogState::Terminated) return false;
    if(!(callId==msg.callId)) return false;
    // RFC 3261 §12.2.2: dialog matching is direction-dependent, not role-dependent.
    //
    //   Incoming REQUEST (BYE, re-INVITE, INFO …)
    //     The sender always places our tag in To and their tag in From,
    //     regardless of whether we are UAC or UAS for the original dialog.
    //       localTag  == msg.to.tag
    //       remoteTag == msg.from.tag
    //
    //   Response to one of our outgoing requests (200 OK to INVITE/BYE …)
    //     We always placed our tag in From of the request; the response
    //     echoes it back in From unchanged.
    //       localTag  == msg.from.tag
    //       remoteTag == msg.to.tag
    //
    // The old code used the UAC branch unconditionally for UAC dialogs, which
    // meant it compared localTag against msg.from.tag even for incoming BYEs,
    // where msg.from.tag is the *remote* party's tag.  That caused dlg_.find()
    // to return nullptr for every incoming BYE on an outbound call, so
    // handleBye() never fired onBye() and call_and_record hung until timeout.
    if(msg.isRequest) {
        // Incoming in-dialog request: we are always To.
        bool toOk  = localTag.eq(msg.to.tag.c_str(),msg.to.tag.len);
        bool fromOk= remoteTag.empty()||remoteTag.eq(msg.from.tag.c_str(),msg.from.tag.len);
        return toOk && fromOk;
    } else {
        // Response to our outgoing request: we are always From.
        bool fromOk= localTag.eq(msg.from.tag.c_str(),msg.from.tag.len);
        bool toOk  = remoteTag.empty()||remoteTag.eq(msg.to.tag.c_str(),msg.to.tag.len);
        return fromOk && toOk;
    }
}

void DialogLayer::update(Dialog& d, const SipMessage& msg, bool isLocal) {
    if(d.state==DialogState::Terminated) return;
    if(msg.isRequest) {
        if(!isLocal) d.remoteCSeq=msg.cseq.seq;
        if(msg.method==Method::BYE) d.state=DialogState::Terminated;
        if(msg.hasContact) d.remoteTarget.assign(msg.contact.uri.c_str(),msg.contact.uri.len);
    } else {
        if(msg.isProvisional()&&!msg.to.tag.empty()&&d.state==DialogState::Null) {
            d.state=DialogState::Early;
            if(d.isUAC&&d.remoteTag.empty()) d.remoteTag=msg.to.tag;
        } else if(msg.is2xx()) {
            d.state=DialogState::Confirmed;
            if(d.isUAC&&d.remoteTag.empty()) d.remoteTag=msg.to.tag;
            if(msg.hasContact) d.remoteTarget.assign(msg.contact.uri.c_str(),msg.contact.uri.len);
            // Build route set (UAC reverses Record-Route)
            if(!msg.recordRoute.empty()&&d.routeSet.count==0) {
                URI hops[RouteSet::Cap]; uint8_t nh=0;
                const char* p=msg.recordRoute.c_str(),*end=p+msg.recordRoute.len;
                while(p<end&&nh<RouteSet::Cap) {
                    while(p<end&&(*p==' '||*p==','))++p; if(p>=end) break;
                    const char* lb=(const char*)memchr(p,'<',(size_t)(end-p)); if(!lb) break; ++lb;
                    const char* rb=(const char*)memchr(lb,'>',(size_t)(end-lb)); if(!rb) break;
                    hops[nh++].assign(lb,(size_t)(rb-lb)); p=rb+1;
                }
                for(int i=nh-1;i>=0;--i) d.routeSet.push(hops[i].c_str(),hops[i].len);
            }
        } else if(msg.statusCode>=300) {
            d.state=DialogState::Terminated;
        }
    }
}

Dialog* DialogLayer::find(const SipMessage& msg)  { return pool_.find([&](Dialog& d){return d.matches(msg);}); }
Dialog* DialogLayer::findById(DialogId id)        { return pool_.find([&](Dialog& d){return d.id==id;}); }
void    DialogLayer::terminate(Dialog& d)         { d.state=DialogState::Terminated; pool_.release(&d); }

} // namespace sip

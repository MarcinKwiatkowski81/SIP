// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

// Sdp.cpp – SDP parser/serialiser (RFC 8866) + Offer/Answer (RFC 3264)
#include "Sdp.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cctype>

namespace sip {

const RtpMap* MediaSection::findByPT(uint8_t pt) const {
    for(uint8_t i=0;i<codecCount;++i) if(codecs[i].pt==pt) return &codecs[i];
    return nullptr;
}
const RtpMap* MediaSection::findByName(const char* n) const {
    for(uint8_t i=0;i<codecCount;++i) if(strcasecmp(codecs[i].encoding.c_str(),n)==0) return &codecs[i];
    return nullptr;
}

// ── Parse ─────────────────────────────────────────────────────────────────────
Result<SdpSession> SdpSession::parse(const char* data, size_t len) {
    SdpSession s; s.sessionName.assign("-",1);
    MediaSection* cur=nullptr;
    const char* p=data, *end=data+len;
    while(p<end) {
        // Skip CR
        if(*p=='\r'){++p; continue;}
        if(p>=end) break;
        char type=*p; if(p+1>=end||*(p+1)!='='){ while(p<end&&*p!='\n')++p; if(p<end)++p; continue; }
        const char* val=p+2;
        const char* lf=(const char*)memchr(val,'\n',(size_t)(end-val));
        size_t vl=lf?(size_t)(lf-val):(size_t)(end-val);
        // trim CR
        while(vl&&(val[vl-1]=='\r'||val[vl-1]==' ')) --vl;
        char vbuf[256]={};
        size_t cp=vl<255?vl:255; memcpy(vbuf,val,cp);

        switch(type) {
        case 'v': s.version=(uint32_t)strtoul(vbuf,nullptr,10); break;
        case 'o': {
            // username sess-id sess-version IN IP4 addr
            char *t1,*t2,*t3,*t4,*t5;
            char ob[256]; memcpy(ob,vbuf,sizeof ob);
            t1=strtok(ob," "); if(t1) s.originUser.assign(t1,strlen(t1));
            t2=strtok(nullptr," "); if(t2) s.sessionId=(uint64_t)strtoull(t2,nullptr,10);
            t3=strtok(nullptr," "); if(t3) s.sessionVer=(uint64_t)strtoull(t3,nullptr,10);
            t4=strtok(nullptr," "); // IN
            (void)t4;
            t5=strtok(nullptr," "); // IP4/IP6
            char* addr=strtok(nullptr," "); if(addr) s.connAddr.assign(addr,strlen(addr));
            break;
        }
        case 's': s.sessionName.assign(vbuf,vl); break;
        case 'c': {
            // IN IP4 addr  or  IN IP6 addr
            char cb[128]; memcpy(cb,vbuf,sizeof cb);
            strtok(cb," "); strtok(nullptr," "); char* addr=strtok(nullptr," /");
            if(addr){ if(cur) cur->connAddr.assign(addr,strlen(addr)); else s.connAddr.assign(addr,strlen(addr)); }
            break;
        }
        case 't': break; // ignore timing
        case 'm': {
            if(s.mediaCount>=SIP_MAX_MEDIA) break;
            cur=&s.media[s.mediaCount++];
            // audio 12345 RTP/AVP 0 8 101
            char mb[256]; memcpy(mb,vbuf,sizeof mb);
            char* mtype=strtok(mb," ");
            if(mtype){
                if     (!strcmp(mtype,"audio"))       cur->type=MediaType::Audio;
                else if(!strcmp(mtype,"video"))       cur->type=MediaType::Video;
                else if(!strcmp(mtype,"text"))        cur->type=MediaType::Text;
                else                                   cur->type=MediaType::Application;
            }
            char* portS=strtok(nullptr," "); if(portS) cur->port=(uint16_t)strtoul(portS,nullptr,10);
            char* proto=strtok(nullptr," "); if(proto) cur->proto.assign(proto,strlen(proto));
            // Remaining tokens = payload types
            char* pt; while((pt=strtok(nullptr," "))!=nullptr) {
                if(cur->codecCount>=SIP_MAX_CODECS) break;
                RtpMap r; r.pt=(uint8_t)strtoul(pt,nullptr,10);
                // Static PT names
                if     (r.pt==0)  { r.encoding.assign("PCMU",4); r.clockRate=8000; }
                else if(r.pt==8)  { r.encoding.assign("PCMA",4); r.clockRate=8000; }
                else if(r.pt==101){ r.encoding.assign("telephone-event",15); r.clockRate=8000; }
                cur->codecs[cur->codecCount++]=r;
            }
            break;
        }
        case 'a': {
            // Attribute: name or name:value
            const char* col=(const char*)memchr(vbuf,':',vl);
            const char* aname=vbuf;
            size_t anl=col?(size_t)(col-vbuf):vl;
            const char* aval=col?col+1:nullptr;
            size_t avl=col?vl-(size_t)(aval-vbuf):0;
            if(!cur) break; // session-level attrs ignored for now
            if(strncmp(aname,"rtpmap",anl)==0&&aval) {
                // PT encoding/clockRate[/channels]
                char ab[128]={}; memcpy(ab,aval,avl<127?avl:127);
                uint8_t pt=(uint8_t)strtoul(ab,nullptr,10);
                char* sp=strchr(ab,' '); if(!sp) break; ++sp;
                char* sl=strchr(sp,'/');
                size_t enl=sl?(size_t)(sl-sp):strlen(sp);
                for(uint8_t i=0;i<cur->codecCount;++i) if(cur->codecs[i].pt==pt) {
                    cur->codecs[i].encoding.assign(sp,enl);
                    if(sl) cur->codecs[i].clockRate=(uint32_t)strtoul(sl+1,nullptr,10);
                    char* sl2=sl?strchr(sl+1,'/'):nullptr;
                    if(sl2) cur->codecs[i].channels=(uint8_t)strtoul(sl2+1,nullptr,10);
                }
            } else if(strncmp(aname,"fmtp",anl)==0&&aval) {
                char ab[128]={}; memcpy(ab,aval,avl<127?avl:127);
                uint8_t pt=(uint8_t)strtoul(ab,nullptr,10);
                char* sp=strchr(ab,' '); if(!sp) break;
                for(uint8_t i=0;i<cur->codecCount;++i) if(cur->codecs[i].pt==pt)
                    cur->codecs[i].fmtp.assign(sp+1,strlen(sp+1));
            } else if(strncmp(aname,"sendrecv",anl)==0) cur->dir=MediaDir::SendRecv;
            else if(strncmp(aname,"sendonly",anl)==0) cur->dir=MediaDir::SendOnly;
            else if(strncmp(aname,"recvonly",anl)==0) cur->dir=MediaDir::RecvOnly;
            else if(strncmp(aname,"inactive",anl)==0) cur->dir=MediaDir::Inactive;
            break;
        }
        }
        p=lf?lf+1:end;
    }
    return s;
}

// ── Format ────────────────────────────────────────────────────────────────────
size_t SdpSession::format(char* buf, size_t sz) const {
    const char* addr=connAddr.empty()?"127.0.0.1":connAddr.c_str();
    const char* user=originUser.empty()?"-":originUser.c_str();
    int n=snprintf(buf,sz,
        "v=0\r\no=%s %llu %llu IN IP4 %s\r\ns=%s\r\nc=IN IP4 %s\r\nt=0 0\r\n",
        user,(unsigned long long)sessionId,(unsigned long long)sessionVer,
        addr,sessionName.empty()?"-":sessionName.c_str(),addr);
    for(uint8_t mi=0;mi<mediaCount&&(size_t)n<sz;++mi) {
        const MediaSection& m=media[mi];
        const char* mtype=(m.type==MediaType::Audio)?"audio":(m.type==MediaType::Video)?"video":(m.type==MediaType::Text)?"text":"application";
        n+=snprintf(buf+n,sz-n,"m=%s %u %s",mtype,m.port,m.proto.empty()?"RTP/AVP":m.proto.c_str());
        for(uint8_t i=0;i<m.codecCount&&(size_t)n<sz;++i)
            n+=snprintf(buf+n,sz-n," %u",m.codecs[i].pt);
        if((size_t)n<sz) { memcpy(buf+n,"\r\n",2); n+=2; }
        for(uint8_t i=0;i<m.codecCount&&(size_t)n<sz;++i) {
            const RtpMap& r=m.codecs[i];
            if(!r.encoding.empty())
                n+=snprintf(buf+n,sz-n,"a=rtpmap:%u %s/%u%s\r\n",r.pt,r.encoding.c_str(),r.clockRate,r.channels>1?"/2":"");
            if(!r.fmtp.empty())
                n+=snprintf(buf+n,sz-n,"a=fmtp:%u %s\r\n",r.pt,r.fmtp.c_str());
        }
        const char* dirStr=(m.dir==MediaDir::SendOnly)?"sendonly":(m.dir==MediaDir::RecvOnly)?"recvonly":(m.dir==MediaDir::Inactive)?"inactive":"sendrecv";
        if((size_t)n<sz) n+=snprintf(buf+n,sz-n,"a=%s\r\n",dirStr);
        if(!m.connAddr.empty()&&(size_t)n<sz)
            n+=snprintf(buf+n,sz-n,"c=IN IP4 %s\r\n",m.connAddr.c_str());
    }
    if(n<0||(size_t)n>=sz) return 0;
    return (size_t)n;
}

// ── Offer/Answer ──────────────────────────────────────────────────────────────
SdpSession SdpSession::makeOffer(const CodecRegistry& reg,
                                  const char* localAddr, uint16_t rtpPort,
                                  bool includeVideo) {
    SdpSession s; s.connAddr.assign(localAddr,strlen(localAddr));
    s.originUser.assign("sip_stack",9); s.sessionName.assign("SIP Call",8);
    s.sessionId=(uint64_t)rand()*rand(); s.sessionVer=s.sessionId;
    if(s.mediaCount<SIP_MAX_MEDIA) {
        MediaSection& m=s.media[s.mediaCount++];
        m.type=MediaType::Audio; m.port=rtpPort; m.proto.assign("RTP/AVP",7); m.dir=MediaDir::SendRecv;
        for(size_t i=0;i<reg.count()&&m.codecCount<SIP_MAX_CODECS;++i) {
            const ICodec* c=reg.at(i);
            RtpMap r; r.pt=c->payloadType(); r.clockRate=c->clockRate();
            r.encoding.assign(c->name(),strlen(c->name())); r.channels=c->channels();
            if(r.pt==101) r.fmtp.assign("0-15",4);
            m.codecs[m.codecCount++]=r;
        }
    }
    (void)includeVideo; // future
    return s;
}

SdpSession SdpSession::makeAnswer(const SdpSession& offer,
                                   const CodecRegistry& reg,
                                   const char* localAddr, uint16_t rtpPort) {
    SdpSession s; s.connAddr.assign(localAddr,strlen(localAddr));
    s.originUser.assign("sip_stack",9); s.sessionName.assign("SIP Call",8);
    s.sessionId=(uint64_t)rand()*rand(); s.sessionVer=s.sessionId;
    for(uint8_t mi=0;mi<offer.mediaCount&&s.mediaCount<SIP_MAX_MEDIA;++mi) {
        const MediaSection& om=offer.media[mi];
        MediaSection& am=s.media[s.mediaCount++];
        am.type=om.type; am.port=rtpPort; am.proto=om.proto; am.dir=MediaDir::SendRecv;
        // Select intersection: only codecs we support
        for(uint8_t i=0;i<om.codecCount&&am.codecCount<SIP_MAX_CODECS;++i) {
            const RtpMap& or_=om.codecs[i];
            ICodec* lc=reg.findByName(or_.encoding.c_str());
            if(lc) { RtpMap r; r.pt=or_.pt; r.clockRate=or_.clockRate; r.channels=or_.channels; r.encoding=or_.encoding; if(or_.pt==101) r.fmtp.assign("0-15",4); am.codecs[am.codecCount++]=r; }
        }
        // If we support nothing, reflect with port 0
        if(am.codecCount==0) am.port=0;
    }
    return s;
}

const MediaSection* SdpSession::audioMedia() const {
    for(uint8_t i=0;i<mediaCount;++i) if(media[i].type==MediaType::Audio) return &media[i];
    return nullptr;
}
MediaSection* SdpSession::audioMediaMut() {
    for(uint8_t i=0;i<mediaCount;++i) if(media[i].type==MediaType::Audio) return &media[i];
    return nullptr;
}
const RtpMap* SdpSession::negotiatedCodec() const {
    const MediaSection* m=audioMedia();
    return (m&&m->codecCount)?&m->codecs[0]:nullptr;
}

} // namespace sip

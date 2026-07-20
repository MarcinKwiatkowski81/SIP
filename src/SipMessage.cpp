// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

// SipMessage.cpp – SIP parser/formatter + Digest auth (RFC 3261, RFC 7616)
#include "SipMessage.h"
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <cctype>
#include <cstdlib>
#include <algorithm>

namespace sip {

const char* methodName(Method m) {
    switch(m){
    case Method::INVITE:    return "INVITE";
    case Method::ACK:       return "ACK";
    case Method::BYE:       return "BYE";
    case Method::CANCEL:    return "CANCEL";
    case Method::REGISTER:  return "REGISTER";
    case Method::OPTIONS:   return "OPTIONS";
    case Method::PRACK:     return "PRACK";
    case Method::UPDATE:    return "UPDATE";
    case Method::REFER:     return "REFER";
    case Method::NOTIFY:    return "NOTIFY";
    case Method::SUBSCRIBE: return "SUBSCRIBE";
    case Method::INFO:      return "INFO";
    case Method::MESSAGE:   return "MESSAGE";
    case Method::PUBLISH:   return "PUBLISH";
    default:                return "UNKNOWN";
    }
}
Method parseMethod(const char* s,size_t l){
    struct E{const char*n;Method m;};
    static const E t[]={
        {"INVITE",Method::INVITE},{"ACK",Method::ACK},{"BYE",Method::BYE},
        {"CANCEL",Method::CANCEL},{"REGISTER",Method::REGISTER},{"OPTIONS",Method::OPTIONS},
        {"PRACK",Method::PRACK},{"UPDATE",Method::UPDATE},{"REFER",Method::REFER},
        {"NOTIFY",Method::NOTIFY},{"SUBSCRIBE",Method::SUBSCRIBE},{"INFO",Method::INFO},
        {"MESSAGE",Method::MESSAGE},{"PUBLISH",Method::PUBLISH}};
    for(auto& e:t) if(strlen(e.n)==l&&!strncmp(s,e.n,l)) return e.m;
    return Method::Unknown;
}

static const char* skipWS(const char* p,const char* e){
    while(p<e&&(*p==' '||*p=='\t'))++p; return p;
}
static size_t trimLen(const char* s,size_t l){
    while(l&&(s[l-1]=='\r'||s[l-1]==' '||s[l-1]=='\t'))--l; return l;
}
static bool hdrIs(const char* n,size_t nl,const char* f,char c){
    if(nl==1) return tolower((unsigned char)*n)==c;
    return nl==strlen(f)&&strncasecmp(n,f,nl)==0;
}

// ─── Via ──────────────────────────────────────────────────────────────────────
Result<Via> Via::parse(const char* s,size_t len){
    Via v; v.transport.assign("UDP",3);
    const char* p=s,*end=s+len;
    const char* sl=p;
    for(int i=0;i<2;++i){sl=(const char*)memchr(sl,'/',(size_t)(end-sl));if(!sl)break;++sl;}
    if(sl&&sl<end){
        const char* te=sl;while(te<end&&!isspace((unsigned char)*te)&&*te!=';')++te;
        v.transport.assign(sl,(size_t)(te-sl)); p=skipWS(te,end);
    }
    const char* hp=p;
    while(p<end&&*p!=';'&&*p!=','&&!isspace((unsigned char)*p))++p;
    const char* col=(const char*)memchr(hp,':',(size_t)(p-hp));
    if(col){v.host.assign(hp,(size_t)(col-hp));v.port=(uint16_t)strtoul(col+1,nullptr,10);}
    else    v.host.assign(hp,(size_t)(p-hp));
    while(p<end){
        if(*p==';'){++p;
            const char* pk=p; while(p<end&&*p!=';'&&*p!=',')++p;
            size_t kl=(size_t)(p-pk);
            if     (strncasecmp(pk,"branch=",  7)==0) v.branch.assign(pk+7,kl-7);
            else if(strncasecmp(pk,"received=",9)==0) v.received.assign(pk+9,kl-9);
            else if(strncasecmp(pk,"rport=",   6)==0) v.rportVal=(uint16_t)strtoul(pk+6,nullptr,10);
            else if(strncasecmp(pk,"rport",    5)==0) v.rport=true;
            else if(strncasecmp(pk,"lr",       2)==0) v.lr=true;
        } else ++p;
    }
    return v;
}
int Via::format(char* buf,size_t sz) const {
    int n=snprintf(buf,sz,"SIP/2.0/%s %s",transport.empty()?"UDP":transport.c_str(),host.c_str());
    if(port&&(size_t)n<sz) n+=snprintf(buf+n,sz-n,":%u",port);
    if(!branch.empty()&&(size_t)n<sz) n+=snprintf(buf+n,sz-n,";branch=%s",branch.c_str());
    if(rport&&(size_t)n<sz){
        if(rportVal) n+=snprintf(buf+n,sz-n,";rport=%u",rportVal);
        else         n+=snprintf(buf+n,sz-n,";rport");
    }
    if(!received.empty()&&(size_t)n<sz) n+=snprintf(buf+n,sz-n,";received=%s",received.c_str());
    return (size_t)n<sz?n:0;
}

// ─── NameAddr ─────────────────────────────────────────────────────────────────
Result<NameAddr> NameAddr::parse(const char* s,size_t len){
    NameAddr na; const char* end=s+len,*p=s;
    while(p<end&&isspace((unsigned char)*p))++p;
    const char* lb=(const char*)memchr(p,'<',(size_t)(end-p));
    if(lb){
        size_t dnl=(size_t)(lb-p);
        while(dnl&&(p[dnl-1]==' '||p[dnl-1]=='"'))--dnl;
        size_t dns=0; while(dns<dnl&&(p[dns]=='"'||p[dns]==' '))++dns;
        na.displayName.assign(p+dns,dnl-dns); ++lb;
        const char* rb=(const char*)memchr(lb,'>',(size_t)(end-lb)); if(!rb) return Err::Parse;
        na.uri.assign(lb,(size_t)(rb-lb)); p=rb+1;
        while(p<end){
            if(*p==';'){++p; const char* pk=p; while(p<end&&*p!=';'&&*p!=',')++p;
                if(strncasecmp(pk,"tag=",4)==0) na.tag.assign(pk+4,(size_t)(p-pk-4));
                else { na.params.append(";",1); na.params.append(pk,(size_t)(p-pk)); }
            } else ++p;
        }
    } else {
        const char* sc=(const char*)memchr(p,';',(size_t)(end-p));
        if(sc){ na.uri.assign(p,(size_t)(sc-p)); p=sc;
            while(p<end){
                if(*p==';'){++p; const char* pk=p; while(p<end&&*p!=';'&&*p!=',')++p;
                    if(strncasecmp(pk,"tag=",4)==0) na.tag.assign(pk+4,(size_t)(p-pk-4));
                } else ++p;
            }
        } else na.uri.assign(p,(size_t)(end-p));
    }
    return na;
}
int NameAddr::format(char* buf,size_t sz,bool withTag) const {
    int n=0;
    if(!displayName.empty()) n+=snprintf(buf+n,sz-n,"\"%s\" ",displayName.c_str());
    n+=snprintf(buf+n,sz-n,"<%s>",uri.c_str());
    if(withTag&&!tag.empty()) n+=snprintf(buf+n,sz-n,";tag=%s",tag.c_str());
    if(!params.empty()) n+=snprintf(buf+n,sz-n,"%s",params.c_str());
    return (size_t)n<sz?n:0;
}
int RouteSet::format(char* buf,size_t sz) const {
    int n=0;
    for(uint8_t i=0;i<count;++i){
        if(i) n+=snprintf(buf+n,sz-n,", ");
        n+=snprintf(buf+n,sz-n,"<%s>",hops[i].c_str());
    }
    return (size_t)n<sz?n:0;
}

// ─── SipMessage::parse ────────────────────────────────────────────────────────
Result<SipMessage> SipMessage::parse(const char* buf,size_t len){
    SipMessage m; const char* p=buf,*end=buf+len;
    const char* lf=(const char*)memchr(p,'\n',(size_t)(end-p)); if(!lf) return Err::Parse;
    size_t ll=trimLen(p,(size_t)(lf-p));
    if(strncmp(p,"SIP/2.0 ",8)==0){
        m.isRequest=false; m.statusCode=(int)strtoul(p+8,nullptr,10);
        const char* rp=p+8;
        while(rp<p+ll&&!isspace((unsigned char)*rp))++rp;
        while(rp<p+ll&&isspace((unsigned char)*rp))++rp;
        m.reason.assign(rp,trimLen(rp,(size_t)(p+ll-rp)));
    } else {
        const char* sp1=(const char*)memchr(p,' ',ll); if(!sp1) return Err::Parse;
        m.method=parseMethod(p,(size_t)(sp1-p));
        const char* uri=sp1+1;
        const char* sp2=(const char*)memchr(uri,' ',(size_t)(p+ll-uri)); if(!sp2) return Err::Parse;
        m.requestUri.assign(uri,(size_t)(sp2-uri));
    }
    p=lf+1;
    while(p<end){
        if(*p=='\r'||*p=='\n'){ if(*p=='\r')++p; if(p<end&&*p=='\n')++p; break; }
        const char* le=(const char*)memchr(p,'\n',(size_t)(end-p)); if(!le) le=end;
        size_t hl=trimLen(p,(size_t)(le-p));
        const char* col=(const char*)memchr(p,':',hl); if(!col){p=le+1;continue;}
        size_t nl=(size_t)(col-p);
        const char* val=skipWS(col+1,p+hl); size_t vl=trimLen(val,(size_t)(p+hl-val));
        const char* n=p;
        if     (hdrIs(n,nl,"Via",'v'))         { if(m.viaCount<SIP_MAX_VIA){auto r=Via::parse(val,vl);if(r.ok())m.via[m.viaCount++]=*r;} }
        else if(hdrIs(n,nl,"From",'f'))         { auto r=NameAddr::parse(val,vl);if(r.ok())m.from=*r; }
        else if(hdrIs(n,nl,"To",'t'))           { auto r=NameAddr::parse(val,vl);if(r.ok())m.to=*r; }
        else if(hdrIs(n,nl,"Call-ID",'i'))      { m.callId.assign(val,vl); }
        else if(hdrIs(n,nl,"CSeq",0))           { m.cseq.seq=(uint32_t)strtoul(val,nullptr,10); const char* mp=val; while(mp<val+vl&&!isspace((unsigned char)*mp))++mp; while(mp<val+vl&&isspace((unsigned char)*mp))++mp; m.cseq.method=parseMethod(mp,vl-(size_t)(mp-val)); }
        else if(hdrIs(n,nl,"Max-Forwards",0))   { m.maxForwards=(uint32_t)strtoul(val,nullptr,10); }
        else if(hdrIs(n,nl,"Contact",'m'))      { if(!m.hasContact){auto r=NameAddr::parse(val,vl);if(r.ok()){m.contact=*r;m.hasContact=true;}} }
        else if(hdrIs(n,nl,"Content-Type",'c')) { m.contentType.assign(val,vl); }
        else if(hdrIs(n,nl,"Content-Length",'l')){ m.contentLen=(uint32_t)strtoul(val,nullptr,10); }
        else if(hdrIs(n,nl,"Expires",0))        { m.expires=(uint32_t)strtoul(val,nullptr,10); }
        else if(hdrIs(n,nl,"WWW-Authenticate",0)){ m.wwwAuth.assign(val,vl); }
        else if(hdrIs(n,nl,"Proxy-Authenticate",0)){ m.proxyAuth.assign(val,vl); }
        else if(hdrIs(n,nl,"Authorization",0))  { m.authorization.assign(val,vl); }
        else if(hdrIs(n,nl,"Proxy-Authorization",0)){ m.proxyAuthorization.assign(val,vl); }
        else if(hdrIs(n,nl,"Supported",'k'))    { m.supported.assign(val,vl); }
        else if(hdrIs(n,nl,"Require",0))        { m.require.assign(val,vl); }
        else if(hdrIs(n,nl,"Record-Route",0))   { if(!m.recordRoute.empty())m.recordRoute.append(", ",2); m.recordRoute.append(val,vl); }
        else if(hdrIs(n,nl,"Route",0))          { if(!m.route.empty())m.route.append(", ",2); m.route.append(val,vl); }
        else if(hdrIs(n,nl,"Allow",0))          { m.allow.assign(val,vl); }
        else if(hdrIs(n,nl,"User-Agent",0))     { m.userAgent.assign(val,vl); }
        else if(hdrIs(n,nl,"Server",0))         { m.server.assign(val,vl); }
        else if(hdrIs(n,nl,"Min-Expires",0))    { m.minExpires=(int)strtoul(val,nullptr,10); }
        p=le+1;
    }
    if(p<end&&m.contentLen>0){ m.body=p; m.bodyLen=std::min((size_t)m.contentLen,(size_t)(end-p)); }
    return m;
}

// ─── SipMessage::format ───────────────────────────────────────────────────────
size_t SipMessage::format(char* buf,size_t sz) const {
    int n=0;
    auto Wf=[&](const char* fmt,...){
        if(n<0||(size_t)n>=sz) return;
        va_list ap; va_start(ap,fmt);
        int r=vsnprintf(buf+n,(int)(sz-n),fmt,ap); va_end(ap);
        if(r<0||(size_t)(n+r)>=sz) n=-1; else n+=r;
    };
    if(isRequest) Wf("%s %s SIP/2.0\r\n",methodName(method),requestUri.c_str());
    else          Wf("SIP/2.0 %d %s\r\n",statusCode,reason.c_str());
    for(int i=0;i<viaCount;++i){ char vb[512]; if(via[i].format(vb,sizeof vb)) Wf("Via: %s\r\n",vb); }
    { char fb[512]; from.format(fb,sizeof fb,true);   if(*fb) Wf("From: %s\r\n",fb); }
    { char tb[512]; to.format(tb,sizeof tb,true);     if(*tb) Wf("To: %s\r\n",tb); }
    Wf("Call-ID: %s\r\n",callId.c_str());
    Wf("CSeq: %u %s\r\n",cseq.seq,methodName(cseq.method));
    if(isRequest) Wf("Max-Forwards: %u\r\n",maxForwards);
    if(hasContact){ char cb[512]; contact.format(cb,sizeof cb,false); Wf("Contact: %s\r\n",cb); }
    if(expires)  Wf("Expires: %u\r\n",expires);
    if(!allow.empty())         Wf("Allow: %s\r\n",allow.c_str());
    if(!supported.empty())     Wf("Supported: %s\r\n",supported.c_str());
    if(!require.empty())       Wf("Require: %s\r\n",require.c_str());
    if(!recordRoute.empty())   Wf("Record-Route: %s\r\n",recordRoute.c_str());
    if(!route.empty())         Wf("Route: %s\r\n",route.c_str());
    if(!wwwAuth.empty())       Wf("WWW-Authenticate: %s\r\n",wwwAuth.c_str());
    if(!proxyAuth.empty())     Wf("Proxy-Authenticate: %s\r\n",proxyAuth.c_str());
    if(!authorization.empty()) Wf("Authorization: %s\r\n",authorization.c_str());
    if(!proxyAuthorization.empty()) Wf("Proxy-Authorization: %s\r\n",proxyAuthorization.c_str());
    if(!userAgent.empty())     Wf("User-Agent: %s\r\n",userAgent.c_str());
    if(!server.empty())        Wf("Server: %s\r\n",server.c_str());
    if(minExpires>=0)          Wf("Min-Expires: %d\r\n",minExpires);
    if(bodyLen&&body){
        Wf("Content-Length: %zu\r\nContent-Type: %s\r\n\r\n",bodyLen,contentType.c_str());
        if(n>=0&&(size_t)n+bodyLen<sz){ memcpy(buf+n,body,bodyLen); n+=(int)bodyLen; } else n=-1;
    } else Wf("Content-Length: 0\r\n\r\n");
    if(n<0) return 0;
    buf[n]=0; return (size_t)n;
}

SipMessage SipMessage::makeResponse(int code,const char* rstr) const {
    SipMessage r; r.isRequest=false; r.statusCode=code; r.reason.assign(rstr,strlen(rstr));
    for(int i=0;i<viaCount;++i) r.via[i]=via[i]; r.viaCount=viaCount;
    r.from=from; r.to=to; r.callId=callId; r.cseq=cseq;
    return r;
}

// ─── MD5 (RFC 1321, portable, no deps) ───────────────────────────────────────
static uint32_t rol32(uint32_t v,int s){return(v<<s)|(v>>(32-s));}
static uint32_t md5F(uint32_t x,uint32_t y,uint32_t z){return(x&y)|((~x)&z);}
static uint32_t md5G(uint32_t x,uint32_t y,uint32_t z){return(x&z)|(y&(~z));}
static uint32_t md5Hf(uint32_t x,uint32_t y,uint32_t z){return x^y^z;}
static uint32_t md5If(uint32_t x,uint32_t y,uint32_t z){return y^(x|(~z));}
static void md5_compress(uint32_t st[4],const uint8_t b[64]){
    uint32_t a=st[0],bv=st[1],c=st[2],d=st[3],x[16];
    for(int i=0;i<16;++i)
        x[i]=(uint32_t)b[i*4]|((uint32_t)b[i*4+1]<<8)|((uint32_t)b[i*4+2]<<16)|((uint32_t)b[i*4+3]<<24);
    static const uint32_t T[64]={0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391};
    static const int R[64]={7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21};
    static const int X[64]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,1,6,11,0,5,10,15,4,9,14,3,8,13,2,7,12,5,8,11,14,1,4,7,10,13,0,3,6,9,12,15,2,0,7,14,5,12,3,10,1,8,15,6,13,4,11,2,9};
    for(int i=0;i<64;++i){
        uint32_t f; int g=X[i];
        if(i<16) f=md5F(bv,c,d); else if(i<32) f=md5G(bv,c,d);
        else if(i<48) f=md5Hf(bv,c,d); else f=md5If(bv,c,d);
        f+=a+x[g]+T[i]; a=d; d=c; c=bv; bv=bv+rol32(f,R[i]);
    }
    st[0]+=a; st[1]+=bv; st[2]+=c; st[3]+=d;
}
static void md5_raw(const uint8_t* data,size_t len,uint8_t out[16]){
    uint32_t s[4]={0x67452301,0xefcdab89,0x98badcfe,0x10325476};
    size_t i=0; for(;i+64<=len;i+=64) md5_compress(s,data+i);
    uint8_t pad[128]={}; size_t rem=len-i; memcpy(pad,data+i,rem); pad[rem]=0x80;
    uint64_t bits=(uint64_t)len*8; size_t pl=(rem<56)?64:128;
    for(int j=0;j<8;++j) pad[pl-8+j]=(uint8_t)(bits>>(j*8));
    md5_compress(s,pad); if(pl==128) md5_compress(s,pad+64);
    for(int j=0;j<4;++j) for(int k=0;k<4;++k) out[j*4+k]=(uint8_t)(s[j]>>(k*8));
}

namespace auth {

static void toHex(const uint8_t* d,char* o){
    static const char h[]="0123456789abcdef";
    for(int i=0;i<16;++i){o[i*2]=h[d[i]>>4];o[i*2+1]=h[d[i]&0xF];} o[32]=0;
}
void md5Hex(const void* data,size_t len,char out[33]){
    uint8_t d[16]; md5_raw((const uint8_t*)data,len,d); toHex(d,out);
}
void md5HexTwo(const char* a,const char* b,char out[33]){
    char tmp[512]; int l=snprintf(tmp,sizeof tmp,"%s:%s",a,b);
    uint8_t d[16]; md5_raw((const uint8_t*)tmp,(size_t)l,d); toHex(d,out);
}
void md5HexThree(const char* a,const char* b,const char* c,char out[33]){
    char tmp[512]; int l=snprintf(tmp,sizeof tmp,"%s:%s:%s",a,b,c);
    uint8_t d[16]; md5_raw((const uint8_t*)tmp,(size_t)l,d); toHex(d,out);
}

Result<Challenge> parseChallenge(const char* s,size_t len){
    Challenge ch; ch.algorithm.assign("MD5",3);
    const char* p=s,*end=s+len;
    if(strncasecmp(p,"Digest ",7)==0) p+=7;
    while(p<end){
        while(p<end&&(*p==' '||*p==','||*p=='\t'))++p;
        const char* kn=p; while(p<end&&*p!='=')++p; if(p>=end) break;
        size_t kl=(size_t)(p-kn); ++p;
        bool q=(p<end&&*p=='"'); if(q)++p;
        const char* vn=p;
        if(q) while(p<end&&*p!='"')++p; else while(p<end&&*p!=','&&*p!=' ')++p;
        size_t vl=(size_t)(p-vn); if(q&&p<end)++p;
        if     (strncasecmp(kn,"realm",    kl)==0) ch.realm.assign(vn,vl);
        else if(strncasecmp(kn,"nonce",    kl)==0) ch.nonce.assign(vn,vl);
        else if(strncasecmp(kn,"algorithm",kl)==0) ch.algorithm.assign(vn,vl);
        else if(strncasecmp(kn,"qop",      kl)==0) ch.qop.assign(vn,vl);
        else if(strncasecmp(kn,"opaque",   kl)==0) ch.opaque.assign(vn,vl);
        else if(strncasecmp(kn,"stale",    kl)==0) ch.stale=(strncasecmp(vn,"true",4)==0);
    }
    if(ch.realm.empty()||ch.nonce.empty()) return Err::Parse;
    return ch;
}

int buildAuthHeader(const Challenge& ch,Method method,const char* uri,
                    const char* user,const char* pass,uint32_t nc,char* buf,size_t bufsz){
    char ha1[33],ha2[33],resp[33],tmp[512];
    snprintf(tmp,sizeof tmp,"%s:%s:%s",user,ch.realm.c_str(),pass);
    md5Hex(tmp,strlen(tmp),ha1);
    snprintf(tmp,sizeof tmp,"%s:%s",methodName(method),uri);
    md5Hex(tmp,strlen(tmp),ha2);
    char cnonce[17]; snprintf(cnonce,sizeof cnonce,"%08x%08x",(uint32_t)rand(),(uint32_t)rand());
    char ncStr[9];   snprintf(ncStr, sizeof ncStr, "%08x",nc);
    bool hasQop=strstr(ch.qop.c_str(),"auth")!=nullptr;
    if(hasQop){ snprintf(tmp,sizeof tmp,"%s:%s:%s:%s:%s:%s",ha1,ch.nonce.c_str(),ncStr,cnonce,"auth",ha2); md5Hex(tmp,strlen(tmp),resp); }
    else       { snprintf(tmp,sizeof tmp,"%s:%s:%s",ha1,ch.nonce.c_str(),ha2); md5Hex(tmp,strlen(tmp),resp); }
    int n=snprintf(buf,bufsz,"Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\"",user,ch.realm.c_str(),ch.nonce.c_str(),uri,resp);
    if(hasQop&&(size_t)n<bufsz) n+=snprintf(buf+n,bufsz-n,", qop=auth, nc=%s, cnonce=\"%s\"",ncStr,cnonce);
    if(!ch.opaque.empty()&&(size_t)n<bufsz) n+=snprintf(buf+n,bufsz-n,", opaque=\"%s\"",ch.opaque.c_str());
    if(!ch.algorithm.empty()&&(size_t)n<bufsz) n+=snprintf(buf+n,bufsz-n,", algorithm=%s",ch.algorithm.c_str());
    return ((size_t)n<bufsz)?n:0;
}

} // namespace auth
} // namespace sip

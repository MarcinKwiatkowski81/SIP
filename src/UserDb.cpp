// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

// UserDb.cpp
#include "UserDb.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cctype>

namespace sip {

// Use the portable MD5 from SipMessage.cpp via forward-declare
namespace auth {
    void md5Hex(const void* data, size_t len, char out[33]);
}

UserDb::UserDb() { memset(entries_, 0, sizeof entries_); }
UserDb::~UserDb() { pthread_mutex_destroy(&mu_); }

void UserDb::ha1(const char* user, const char* realm, const char* pass, char out[33]) {
    char tmp[256]; int n=snprintf(tmp,sizeof tmp,"%s:%s:%s",user,realm,pass);
    auth::md5Hex(tmp,(size_t)n,out);
}

bool UserDb::add(const char* username, const char* password, const char* realm,
                 bool canReg, bool canCall, bool isAdmin) {
    pthread_mutex_lock(&mu_);
    // Update existing
    for (auto& e : entries_) {
        if (e.used && e.username==username) {
            e.password.assign(password,strlen(password));
            e.realm.assign(realm,strlen(realm));
            e.canRegister=canReg; e.canCall=canCall; e.isAdmin=isAdmin;
            pthread_mutex_unlock(&mu_); return true;
        }
    }
    // Add new
    for (auto& e : entries_) {
        if (!e.used) {
            e.used=true; e.enabled=true;
            e.username.assign(username,strlen(username));
            e.password.assign(password,strlen(password));
            e.realm.assign(realm ? realm : "", realm ? strlen(realm) : 0);
            e.canRegister=canReg; e.canCall=canCall; e.isAdmin=isAdmin;
            pthread_mutex_unlock(&mu_); return true;
        }
    }
    pthread_mutex_unlock(&mu_); return false; // full
}

bool UserDb::remove(const char* username) {
    pthread_mutex_lock(&mu_);
    for (auto& e : entries_) {
        if (e.used && e.username==username) { e.used=false; pthread_mutex_unlock(&mu_); return true; }
    }
    pthread_mutex_unlock(&mu_); return false;
}

bool UserDb::setEnabled(const char* username, bool enabled) {
    pthread_mutex_lock(&mu_);
    for (auto& e : entries_) {
        if (e.used && e.username==username) { e.enabled=enabled; pthread_mutex_unlock(&mu_); return true; }
    }
    pthread_mutex_unlock(&mu_); return false;
}

UserEntry* UserDb::findM(const char* username) {
    for (auto& e : entries_) if (e.used && e.username==username) return &e;
    return nullptr;
}
const UserEntry* UserDb::find(const char* username) const {
    for (const auto& e : entries_) if (e.used && e.username==username) return &e;
    return nullptr;
}

bool UserDb::verifyDigest(const char* username, const auth::Challenge& ch,
                          Method method, const char* uri,
                          const char* response, uint32_t nc,
                          const char* cnonce, const char* qop) const {
    pthread_mutex_lock(&mu_);
    const UserEntry* u = find(username);
    if (!u || !u->enabled) { pthread_mutex_unlock(&mu_); return false; }

    // Compute HA1
    char ha1[33];
    const char* pw = u->password.c_str();
    const char* rl = u->realm.empty() ? ch.realm.c_str() : u->realm.c_str();
    if (strncmp(pw,"ha1:",4)==0) {
        strncpy(ha1, pw+4, 32); ha1[32]=0;
    } else {
        UserDb::ha1(username, rl, pw, ha1);
    }

    // Compute HA2
    char ha2[33], tmp[512], resp[33];
    snprintf(tmp,sizeof tmp,"%s:%s",methodName(method),uri);
    auth::md5Hex(tmp,strlen(tmp),ha2);

    // Compute response
    bool hasQop = qop && strncmp(qop,"auth",4)==0;
    if (hasQop) {
        char ncStr[9]; snprintf(ncStr,sizeof ncStr,"%08x",nc);
        snprintf(tmp,sizeof tmp,"%s:%s:%s:%s:%s:%s",ha1,ch.nonce.c_str(),ncStr,cnonce,"auth",ha2);
    } else {
        snprintf(tmp,sizeof tmp,"%s:%s:%s",ha1,ch.nonce.c_str(),ha2);
    }
    auth::md5Hex(tmp,strlen(tmp),resp);
    pthread_mutex_unlock(&mu_);

    return (strcmp(resp, response) == 0);
}

int UserDb::load(const char* path) {
    FILE* f = fopen(path,"r"); if(!f) return -1;
    char line[512]; int n=0;
    while (fgets(line,sizeof line,f)) {
        // skip comments and blank lines
        if (line[0]=='#'||line[0]=='\n'||line[0]=='\r') continue;
        // format: username:password:realm:flags
        char user[64]={},pass[64]={},realm[64]={},flags[16]={};
        if (sscanf(line,"%63[^:]:%63[^:]:%63[^:]:%15s",user,pass,realm,flags)>=2) {
            bool canReg=true, canCall=true, isAdmin=false;
            for (char* p=flags; *p; ++p) {
                if (*p=='R'||*p=='r') canReg=true;
                if (*p=='C'||*p=='c') canCall=true;
                if (*p=='A'||*p=='a') isAdmin=true;
                if (*p=='-') canReg=canCall=false;
            }
            if (add(user,pass,*realm?realm:nullptr,canReg,canCall,isAdmin)) ++n;
        }
    }
    fclose(f); return n;
}

bool UserDb::save(const char* path) const {
    FILE* f = fopen(path,"w"); if(!f) return false;
    fprintf(f,"# SIP user database: username:password:realm:flags\n");
    fprintf(f,"# flags: R=register C=call A=admin  (- = all disabled)\n");
    pthread_mutex_lock(&mu_);
    for (const auto& e : entries_) {
        if (!e.used) continue;
        char flags[8]="";
        if (e.canRegister) strcat(flags,"R");
        if (e.canCall)     strcat(flags,"C");
        if (e.isAdmin)     strcat(flags,"A");
        if (!*flags) strcpy(flags,"-");
        fprintf(f,"%s:%s:%s:%s\n",e.username.c_str(),e.password.c_str(),
                e.realm.c_str(),flags);
    }
    pthread_mutex_unlock(&mu_);
    fclose(f); return true;
}

size_t UserDb::count() const {
    size_t n=0;
    pthread_mutex_lock(&mu_);
    for (const auto& e : entries_) if (e.used) ++n;
    pthread_mutex_unlock(&mu_);
    return n;
}

void UserDb::printAll() const {
    printf("%-20s %-30s %-20s %s\n","User","Realm","Flags","Status");
    printf("%-20s %-30s %-20s %s\n","----","-----","-----","------");
    pthread_mutex_lock(&mu_);
    for (const auto& e : entries_) {
        if (!e.used) continue;
        char flags[16]="";
        if (e.canRegister) strcat(flags,"register ");
        if (e.canCall)     strcat(flags,"call ");
        if (e.isAdmin)     strcat(flags,"admin ");
        printf("%-20s %-30s %-20s %s\n",
               e.username.c_str(), e.realm.c_str(), flags,
               e.enabled ? "enabled" : "DISABLED");
    }
    pthread_mutex_unlock(&mu_);
}

} // namespace sip

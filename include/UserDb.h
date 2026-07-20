// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

/**
 * @file UserDb.h
 * @brief Thread-safe SIP credential/user database API.
 *
 * File format (one user per line):
 * `username:password:realm:flags`
 * where flags are `R` (register), `C` (call), `A` (admin).
 */
#pragma once
#include "common.h"
#include "SipMessage.h"   // for auth::
#include <pthread.h>

namespace sip {

/** @brief Single user record used by UserDb. */
struct UserEntry {
    /** Username used for auth and extension identity. */
    Str<64>  username;
    /** Plain password or `ha1:<32hex>` digest form. */
    Str<64>  password;   // plain OR "ha1:<32hexchars>"
    /** SIP auth realm for this user. */
    Str<64>  realm;
    /** Whether REGISTER is allowed. */
    bool     canRegister = true;
    /** Whether call placement is allowed. */
    bool     canCall     = true;
    /** Administrative privilege flag. */
    bool     isAdmin     = false;
    /** Enabled/disabled state. */
    bool     enabled     = true;
    /** Internal slot occupancy marker. */
    bool     used        = false;
};

/** @brief In-memory fixed-capacity user and digest verification database. */
class UserDb {
public:
    /** Maximum number of user records. */
    static constexpr size_t MaxUsers = 512;

    /** Construct empty database. */
    UserDb();
    /** Destroy database and mutex resources. */
    ~UserDb();

    /**
     * @brief Load users from text file.
     * @return Number of loaded users, or -1 on error.
     */
    int  load(const char* path);
    /** @brief Save users to text file. */
    bool save(const char* path) const;

    /** @brief Add or update one user entry. */
    bool add(const char* username, const char* password, const char* realm,
             bool canReg = true, bool canCall = true, bool isAdmin = false);
    /** @brief Remove user by username. */
    bool remove(const char* username);
    /** @brief Enable/disable user by username. */
    bool setEnabled(const char* username, bool enabled);

    /** @brief Find user by username; returns null when absent. */
    const UserEntry* find(const char* username) const;

    /**
     * @brief Verify SIP Digest auth response.
     * @return true when response matches stored credentials.
     */
    bool verifyDigest(const char* username, const auth::Challenge& ch,
                      Method method, const char* uri,
                      const char* response, uint32_t nc,
                      const char* cnonce, const char* qop) const;

    /** @brief Count active user records. */
    size_t count() const;
    /** @brief Print user table to stdout. */
    void   printAll() const;

private:
    UserEntry entries_[MaxUsers];
    mutable pthread_mutex_t mu_ = PTHREAD_MUTEX_INITIALIZER;

    UserEntry* findM(const char* username);
    static void ha1(const char* user, const char* realm,
                    const char* pass, char out[33]);
};

} // namespace sip

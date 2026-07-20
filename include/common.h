// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

/**
 * @file common.h
 * @brief Foundation types and compile-time limits for SIP stack.
 */
#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <algorithm>
#include <new>

namespace sip {

/** @brief Generic error codes used by parser, transport, and state layers. */
enum class Err : uint8_t {
    Ok=0, Parse, TooLong, NotFound, Duplicate, BadState,
    Transport, Auth, Resources, Timeout, Rejected,
};

/**
 * @brief Value-or-error helper for non-allocating APIs.
 * @tparam T Value type held when state is OK.
 */
template<class T> struct Result {
    /** In-place storage for T to avoid heap allocation. */
    alignas(T) uint8_t storage[sizeof(T)] = {};
    /** Error code for this result. */
    Err e;
    /** @brief Construct successful result from value. */
    Result(T v) : e(Err::Ok) { new(storage) T(std::move(v)); }
    /** @brief Construct failed result from error code. */
    Result(Err er) : e(er) {}
    /** @brief True when result contains a value. */
    bool ok()  const { return e == Err::Ok; }
    /** @brief Boolean shorthand for ok(). */
    explicit operator bool() const { return ok(); }
    /** @brief Access contained mutable value. */
    T&       operator*()       { return *reinterpret_cast<T*>(storage); }
    /** @brief Access contained const value. */
    const T& operator*() const { return *reinterpret_cast<const T*>(storage); }
    /** @brief Pointer-style mutable access to contained value. */
    T*       operator->()       { return reinterpret_cast<T*>(storage); }
    /** @brief Pointer-style const access to contained value. */
    const T* operator->() const { return reinterpret_cast<const T*>(storage); }
};
/** @brief Specialization for void-return operations. */
template<> struct Result<void> {
    /** Error code for this result. */
    Err e;
    /** @brief Construct successful void result. */
    Result()       : e(Err::Ok) {}
    /** @brief Construct failed void result from error code. */
    Result(Err er) : e(er) {}
    /** @brief True when operation succeeded. */
    bool ok()  const { return e == Err::Ok; }
    /** @brief Boolean shorthand for ok(). */
    explicit operator bool() const { return ok(); }
};
/** @brief Shorthand for Result<void>. */
using Res = Result<void>;

/**
 * @brief Fixed-size no-heap string with truncating assignments.
 * @tparam N Maximum character length (excluding trailing NUL).
 */
template<size_t N>
struct Str {
    /** Backing storage including trailing NUL. */
    char     buf[N+1] = {};
    /** Current length excluding trailing NUL. */
    uint16_t len      = 0;

    /** @brief Construct empty string. */
    Str() = default;
    /** @brief Construct from C string and optional explicit length. */
    Str(const char* s, size_t l = SIZE_MAX) { assign(s, l == SIZE_MAX ? (s?strlen(s):0) : l); }

    /** @brief Assign from pointer+length (truncates to capacity). */
    void assign(const char* s, size_t l) {
        len = (uint16_t)std::min(l, N);
        if (s && len) memcpy(buf, s, len);
        buf[len] = 0;
    }
    /** @brief Reset to empty. */
    void clear()              { len=0; buf[0]=0; }
    /** @brief Return true when length is zero. */
    bool empty()         const { return len==0; }
    /** @brief Return NUL-terminated C string pointer. */
    const char* c_str()  const { return buf; }
    /** @brief Mutable data pointer. */
    char*       data()         { return buf; }
    /** @brief Set current length and enforce trailing NUL. */
    void setLen(size_t l)     { len=(uint16_t)std::min(l,N); buf[len]=0; }

    /** @brief Append bytes; returns false when truncated. */
    bool append(const char* s, size_t l) {
        size_t add = std::min(l, N - (size_t)len);
        if (add) memcpy(buf+len, s, add);
        len += (uint16_t)add; buf[len] = 0;
        return add == l;
    }
    /** @brief Append single character. */
    bool appendC(char c) { return append(&c, 1); }

    /** @brief Exact binary equality with pointer+length. */
    bool eq(const char* s, size_t l)  const { return len==l && !memcmp(buf,s,l); }
    /** @brief Exact case-sensitive equality with C string. */
    bool operator==(const char* s)    const { return eq(s, strlen(s)); }
    /** @brief Exact case-sensitive equality with another Str. */
    bool operator==(const Str& o)     const { return eq(o.buf, o.len); }
    /** @brief Inequality with C string. */
    bool operator!=(const char* s)    const { return !(*this==s); }
    /** @brief Inequality with another Str. */
    bool operator!=(const Str& o)     const { return !(*this==o); }

    /** @brief ASCII case-insensitive equality check. */
    bool eqi(const char* s, size_t l) const {
        if (len != l) return false;
        for (size_t i=0; i<l; ++i)
            if ((buf[i]|32) != (s[i]|32)) return false;
        return true;
    }
};

/**
 * @brief Non-owning contiguous view of memory.
 * @tparam T Element type.
 */
template<class T>
struct Span {
    /** Pointer to first element (non-owning). */
    T* ptr=nullptr;
    /** Number of elements in span. */
    size_t n=0;
    /** @brief Mutable indexed access. */
    T&       operator[](size_t i)       { return ptr[i]; }
    /** @brief Const indexed access. */
    const T& operator[](size_t i) const { return ptr[i]; }
    /** @brief Iterator begin. */
    T* begin() { return ptr; }
    /** @brief Iterator end. */
    T* end() { return ptr+n; }
    /** @brief Const iterator begin. */
    const T* begin() const { return ptr; }
    /** @brief Const iterator end. */
    const T* end() const { return ptr+n; }
    /** @brief Number of elements in span. */
    size_t size() const { return n; }
    /** @brief True when span has zero elements. */
    bool empty() const { return n==0; }
};

/**
 * @brief Fixed-size object pool with placement-new construction.
 * @tparam T Object type.
 * @tparam N Slot count.
 */
template<class T, size_t N>
struct Pool {
    /** @brief One raw slot in pool backing storage. */
    struct Slot {
        /** Raw aligned bytes for one T instance. */
        alignas(T) uint8_t storage[sizeof(T)];
        /** True when slot currently holds live object. */
        bool used=false;
    };
    /** Slot array storage. */
    Slot slots[N];

    /** @brief Allocate and default-construct one object, or nullptr if full. */
    T* alloc() {
        for (auto& s : slots)
            if (!s.used) { s.used=true; return new(s.storage) T{}; }
        return nullptr;
    }
    /** @brief Destroy and release previously allocated object. */
    void release(T* p) {
        for (auto& s : slots) if (reinterpret_cast<T*>(s.storage)==p) {
            p->~T(); s.used=false; return;
        }
    }
    /** @brief Visit each active object in pool. */
    template<class F> void forEach(F fn) {
        for (auto& s : slots) if (s.used) fn(*reinterpret_cast<T*>(s.storage));
    }
    /** @brief Find first active object matching predicate. */
    template<class F> T* find(F pred) {
        for (auto& s : slots) if (s.used) {
            T* p = reinterpret_cast<T*>(s.storage);
            if (pred(*p)) return p;
        }
        return nullptr;
    }
    /** @brief Count active objects in pool. */
    size_t count() const { size_t c=0; for(auto& s:slots) c+=s.used; return c; }
};

// ── Compile-time limits ────────────────────────────────────────────────────────
#ifndef SIP_MAX_MSG
/** @brief Maximum SIP message size in bytes. */
#  define SIP_MAX_MSG       4096
#endif
#ifndef SIP_MAX_VIA
/** @brief Maximum Via headers stored per message. */
#  define SIP_MAX_VIA       8
#endif
#ifndef SIP_MAX_TXNS
/** @brief Maximum concurrent transactions. */
#  define SIP_MAX_TXNS      64
#endif
#ifndef SIP_MAX_DIALOGS
/** @brief Maximum concurrent dialogs. */
#  define SIP_MAX_DIALOGS   32
#endif
#ifndef SIP_MAX_REGS
/** @brief Maximum registrar entries for legacy fixed tables. */
#  define SIP_MAX_REGS      128
#endif
#ifndef SIP_MAX_CODECS
/** @brief Maximum codecs per offer/registry section. */
#  define SIP_MAX_CODECS    8
#endif
#ifndef SIP_MAX_MEDIA
/** @brief Maximum SDP media sections. */
#  define SIP_MAX_MEDIA     4
#endif
#ifndef SIP_T1
/** @brief SIP Timer T1 in milliseconds. */
#  define SIP_T1            500
#endif
#ifndef SIP_T2
/** @brief SIP Timer T2 in milliseconds. */
#  define SIP_T2            4000
#endif
#ifndef SIP_T4
/** @brief SIP Timer T4 in milliseconds. */
#  define SIP_T4            5000
#endif
#ifndef SIP_UDP_PORT
/** @brief Default SIP UDP port. */
#  define SIP_UDP_PORT      5060
#endif
#ifndef SIP_RTP_BASE_PORT
/** @brief Default RTP base UDP port. */
#  define SIP_RTP_BASE_PORT 16384
#endif

/** @brief Canonical URI string type. */
using URI    = Str<256>;
/** @brief Generic header value string type. */
using HdrVal = Str<256>;
/** @brief SIP tag value string type. */
using Tag    = Str<32>;
/** @brief SIP branch parameter string type. */
using Branch = Str<72>;
/** @brief SIP Call-ID string type. */
using CallId = Str<72>;
/** @brief SIP body scratch buffer string type. */
using BodyStr= Str<1500>;

} // namespace sip

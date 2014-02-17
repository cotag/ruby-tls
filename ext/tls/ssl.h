/*****************************************************************************

$Id$

File:     ssl.h
Date:     30Apr06

Copyright (C) 2006-07 by Francis Cianfrocca. All Rights Reserved.
Gmail: blackhedd

This program is free software; you can redistribute it and/or modify
it under the terms of either: 1) the GNU General Public License
as published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version; or 2) Ruby's License.

See the file COPYING for complete licensing information.

*****************************************************************************/


#ifndef __SslBox__H_
#define __SslBox__H_

#include <iostream>
#include <string>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <assert.h>

#include "page.h"

using namespace std;


/******************
class SslContext_t
******************/

class SslContext_t
{
    public:
        SslContext_t (bool is_server, const string &privkeyfile, const string &certchainfile);
        virtual ~SslContext_t();

    private:
        bool bIsServer;
        SSL_CTX *pCtx;

        EVP_PKEY *PrivateKey;
        X509 *Certificate;

    friend class SslBox_t;
};




typedef struct tls_state_s tls_state_t;



/**************
class SslBox_t
**************/

class SslBox_t
{
    public:
        SslBox_t (tls_state_t *tls_state, bool is_server, const string &privkeyfile, const string &certchainfile, bool verify_peer);
        virtual ~SslBox_t();

        int PutPlaintext (const char*, int);
        int GetPlaintext (char*, int);

        bool PutCiphertext (const char*, int);
        bool CanGetCiphertext();
        int GetCiphertext (char*, int);
        bool IsHandshakeCompleted() { return bHandshakeCompleted; }

        X509 *GetPeerCert();

        void Shutdown();

    protected:
        SslContext_t *Context;

        bool bIsServer;
        bool bHandshakeCompleted;
        bool bVerifyPeer;
        SSL *pSSL;
        BIO *pbioRead;
        BIO *pbioWrite;

        PageList OutboundQ;
};


typedef void (*ssl_close_cb)(const tls_state_t*);
typedef int (*ssl_verify_cb)(const tls_state_t*, const char *cert);
typedef void (*ssl_dispatch_cb)(const tls_state_t*, const char *buffer, int size);
typedef void (*ssl_transmit_cb)(const tls_state_t*, const char *buffer, int size);
typedef void (*ssl_handshake_cb)(const tls_state_t*);

struct tls_state_s {
    int handshake_signaled;

    ssl_close_cb close_cb;
    ssl_verify_cb verify_cb;
    ssl_dispatch_cb dispatch_cb;
    ssl_transmit_cb transmit_cb;
    ssl_handshake_cb handshake_cb;

    SslBox_t* SslBox;
};


extern "C" int ssl_verify_wrapper(int preverify_ok, X509_STORE_CTX *ctx);

extern "C" void start_tls(tls_state_t *tls_state, bool bIsServer, const char *PrivateKeyFilename, const char *CertChainFilename, bool bSslVerifyPeer);
extern "C" void cleanup(tls_state_t *tls_state);
extern "C" void decrypt_data(tls_state_t *tls_state, const char *buffer, int size);
extern "C" void encrypt_data(tls_state_t *tls_state, const char *data, int length);
extern "C" X509 *get_peer_cert(tls_state_t *tls_state);

extern "C" void init_rubytls();


#endif // __SslBox__H_

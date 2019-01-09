#ifndef _SSL_SERVER_HPP__
#define _SSL_SERVER_HPP__

#include <string>
#include <iostream>
#include <boost/asio.hpp>
#include "boost/thread.hpp"
#include "boost/date_time.hpp"
#include "boost/thread/thread_time.hpp"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/ossl_typ.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/modes.h>
#include "ssl_status.hpp"

class SSLServer
{
public:
    SSLServer();
    virtual ~SSLServer(void);

    bool InitSSLServer(const std::string& cert_file, const std::string& key_file);

    bool WriteEncryptSSL(const std::string& msg); // Do encrypt
    bool ReadEncryptBIO(std::string& msg);

    bool WriteDecryptBIO(const std::string& msg); //Do decrypt
    bool ReadDecryptSSL(std::string& msg);

    bool KickHandShake(std::string& msg);
    bool IsHandShakeDone(void);
    bool IsSSLerror(int ret);

    bool SSLAccept(std::string& msg);
    SSLHandler::SSLStatus EncryptSSL(std::string& msg);
    SSLHandler::SSLStatus DecryptSSL(std::string& in_msg, std::string& out_msg);

private:
    SSL_CTX* m_ctx;
    SSL*     m_ssl;

    BIO*        m_rbio;
    BIO*        m_wbio;

    boost::mutex m_mutex;
    boost::condition_variable m_cond;
    int m_retrial_no;
};

#endif // _SSL_SERVER_HPP__

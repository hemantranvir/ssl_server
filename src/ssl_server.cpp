#include "ssl_server.hpp"
#include "ssl_functions.h"

#define MAX_BUF_SIZE 2048

/*
  +---+                             +---+
  | s |-> recv -> BIO_write(rbio) ->| S |-> SSL_read(ssl)  -> IN
  | o |                             | S |
  | c |                             | L |
  | k |<- send <- BIO_read(wbio)  <-|   |<- SSL_write(ssl) <- OUT
  +---+                             +---+

       |<---------crypted--------->|     |<--uncrypted--->|
*/

SSLServer::SSLServer()
    : m_ctx(nullptr)
    , m_ssl(nullptr)
    , m_rbio(nullptr)
    , m_wbio(nullptr)
    , m_retrial_no(5)
{
}

SSLServer::~SSLServer(void)
{
    if (m_ssl) {
        SSL_free(m_ssl);
    }
    if (m_ctx) {
        SSL_CTX_free(m_ctx);
    }
}

bool SSLServer::InitSSLServer(const std::string& cert_file, const std::string& key_file)
{
    boost::mutex::scoped_lock lock(m_mutex);
    SSL_load_error_strings();   
    OpenSSL_add_ssl_algorithms();

    m_ctx = SSL_CTX_new(TLS_server_method());
    if (!m_ctx) {
        std::cout  << "[SSLServer]"<< "Unable to create SSL context" << std::endl;
        return false;
    }

    if (m_ctx == nullptr) {
        return false;
    }

    if (SSL_CTX_use_certificate_file(m_ctx, cert_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
        std::cout  << "[SSLServer]"<< "Cert file is unable" << std::endl;
        return false;
    }

    if (SSL_CTX_use_PrivateKey_file(m_ctx, key_file.c_str(), SSL_FILETYPE_PEM) <= 0 ) {
        std::cout  << "[SSLServer]"<< "Key file is unable" << std::endl;
        return false;
    }


    m_rbio = BIO_new(BIO_s_mem());
    m_wbio = BIO_new(BIO_s_mem());
    m_ssl  = SSL_new(m_ctx);

    if (m_rbio == nullptr || m_wbio == nullptr || m_ssl == nullptr) {
        return false;
    }

    SSL_set_accept_state(m_ssl);
    SSL_set_bio(m_ssl, m_rbio, m_wbio);

    return true;
}

bool SSLServer::WriteDecryptBIO(const std::string& msg)
{
    const char* buf = msg.c_str();
    int len = msg.length();
    int n;

    if (len <= 0 || m_rbio == nullptr) {
        std::cout << "[SSLServer] " << "WriteDecryptBIO len <=0 or m_rbio is null" << std::endl;
        return false;
    }
    while (len > 0) {
        n = BIO_write(m_rbio, buf, len);
        if (n <= 0 && !BIO_should_retry(m_rbio)) {
            return false;
        }
        buf += n;
        len -= n;
    }
    return true;
}

bool SSLServer::ReadDecryptSSL(std::string& msg)
{
    char buf[MAX_BUF_SIZE];
    int ret;
    int n;
    msg.clear();

    if (m_ssl == nullptr) {
        return false;
    }

    do {
        n = SSL_read(m_ssl, buf, sizeof(buf));
        ret = SSL_get_error(m_ssl, n);

        if (IsSSLerror(ret)) {
            std::cout << "[SSLServer] " << "SSL_read failed, n: " << n  << ", SSL_get_error: " << ret << std::endl;

            return false;
        }
        for (int i=0; i<n; ++i) {
            msg += buf[i];
        }
    } while (n > 0);

    return true;
}

bool SSLServer::WriteEncryptSSL(const std::string& msg)
{
    int len = msg.length();
    char* buf = (char*)msg.c_str();
    int ret;
    int n;

    if (len <= 0 || m_ssl == nullptr) {
        return false;
    }
    while (len > 0) {
        n = SSL_write(m_ssl, buf, len);
        ret = SSL_get_error(m_ssl, n);
        if (n < 0 || IsSSLerror(ret)) {
            return false;
        }
        buf += n;
        len -= n;
    }
    return true;
}

bool SSLServer::ReadEncryptBIO(std::string& msg)
{
    char buf[MAX_BUF_SIZE] = {"\0"};
    int n;
    msg.clear();

    if (m_wbio == nullptr) {
        return false;
    }

    do {
        n = BIO_read(m_wbio, buf, sizeof(buf));
        if (n<=0 && !BIO_should_retry(m_wbio)) {
            std::cout << "[SSLServer] " << "No Encrypted message to send" << std::endl;
            return false;
        }
        for (int i=0; i<n; ++i) {
            msg += buf[i];
        }
    } while (n > 0);

    return true;
}

bool SSLServer::KickHandShake(std::string& msg)
{
    int n;
    int ssl_error = SSL_ERROR_NONE;
    int count = m_retrial_no;

    if (m_ssl == nullptr) {
        return false;
    }

    do {
        n = SSL_do_handshake(m_ssl);
        ssl_error = SSL_get_error(m_ssl, n);

        if (ssl_error == SSL_ERROR_WANT_WRITE || ssl_error == SSL_ERROR_WANT_READ) {
            if (!ReadEncryptBIO(msg)) return false;
        }

        --count;
    } while (ssl_error == SSL_ERROR_SSL && count>0);

    if (ssl_error == SSL_ERROR_SSL) {
        return false;
    }

    return true;
}

bool SSLServer::IsHandShakeDone(void)
{
    if (m_ssl) {
        return SSL_is_init_finished(m_ssl) == 1;
    }
    else {
        return false;
    }
}

bool SSLServer::IsSSLerror(int ret)
{
    return (ret == SSL_ERROR_ZERO_RETURN
         || ret == SSL_ERROR_SYSCALL
         || ret == SSL_ERROR_SSL );
}

bool SSLServer::SSLAccept(std::string& msg)
{
    int n = SSL_accept(m_ssl);
    int ret = SSL_get_error(m_ssl, n);
    ReadEncryptBIO(msg);
    return true;
}

SSLHandler::SSLStatus SSLServer::EncryptSSL(std::string& msg)
{
    if (IsHandShakeDone()) {
        if (!WriteEncryptSSL(msg)) {
            std::cout << "[SSLServer] " << "WriteEncryptSSL failed" << std::endl;
            return SSLHandler::kSSLWriteEncryptSSLFail;
        }
        if (!ReadEncryptBIO(msg)) {
            std::cout << "[SSLServer] " << "ReadEncryptBIO failed" << std::endl;
            return SSLHandler::kSSLReadEncryptBIOFail;
        }
    }

    return SSLHandler::kSSLSuccess;
}

SSLHandler::SSLStatus SSLServer::DecryptSSL(std::string& in_msg, std::string& out_msg)
{
    boost::mutex::scoped_lock lock(m_mutex);
    out_msg.clear();

    if (!WriteDecryptBIO(in_msg)) {
        std::cout << "[SSLServer] " << "WriteDecryptBIO failed" << std::endl;
        return SSLHandler::kSSLWriteDecryptBIOFail;
    }

    if (!IsHandShakeDone()) {
        if (!KickHandShake(out_msg)) {
            return SSLHandler::kSSLKickHandShakeFail;
        }

        if (IsHandShakeDone()) {
            if (!SSLAccept(out_msg)) return SSLHandler::kSSLReadEncryptBIOFail;
            return SSLHandler::kSSLHandShakeDone;
        }
        return SSLHandler::kSSLHandShakeInProgress; 
    } else {
        if (!ReadDecryptSSL(in_msg)) {
            std::cout << "[SSLServer] " << "ReadDecryptSSL failed" << std::endl;
            return SSLHandler::kSSLReadDecryptSSLFail;
        }
    }

    return SSLHandler::kSSLSuccess;
}

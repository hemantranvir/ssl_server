#ifndef _SSL_CLIENT_HPP__
#define _SSL_CLIENT_HPP__

#include <string>
#include <algorithm>
#include <poll.h>
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

class SSLClient
{
public:
    SSLClient(int retrial_no);
    SSLClient();
    virtual ~SSLClient(void);

    SSLHandler::SSLStatus InitSSLClient(const std::string& ssl_cadir, const std::string& ssl_cipher);

    bool KickHandShake(std::string& msg);

    SSLHandler::SSLStatus Wait(int timeout);
    SSLHandler::SSLStatus EncryptSSL(std::string& msg);
    SSLHandler::SSLStatus DecryptSSL(std::string& in_msg, std::string& out_msg);
    bool GetMasterSecret(std::vector<unsigned char>& key);
    bool GetReceiveSecrets(std::vector<unsigned char>& rx_iv, std::vector<unsigned char>& rx_key, std::vector<unsigned char>& rx_mac);
    bool GetTransmitSecrets(std::vector<unsigned char>& tx_iv, std::vector<unsigned char>& tx_key, std::vector<unsigned char>& tx_mac);

    bool GetCipherName(std::string& cipher_name);

    bool GetEncryptExpandedKey(std::vector<unsigned char>& expanded_key);
    bool GetDecryptExpandedKey(std::vector<unsigned char>& expanded_key);

    bool EncryptAES(bool encrypt_key, std::vector<unsigned char>& msg, std::vector<unsigned char>& enc_msg);

private:
    bool IsHandShakeDone(void);
    bool IsSSLerror(int ret);
    bool WriteEncryptSSL(const std::string& msg); // Do encrypt
    bool ReadEncryptBIO(std::string& msg);

    bool WriteDecryptBIO(const std::string& msg); //Do decrypt
    bool ReadDecryptSSL(std::string& msg);

    bool FetchMasterSecret();
    bool FetchReceiveSecrets();
    bool FetchTransmitSecrets();

    void KeyExpansionCore(std::vector<unsigned char>& in, int round_no);
    void KeyExpansion(const std::vector<unsigned char>& input_key, std::vector<unsigned char>& expanded_keys);

    void AddRoundKey(unsigned char* state, unsigned char* round_key);
    void MixColumns(unsigned char* state);
    void ShiftRows(unsigned char* state);
    void SubBytes(unsigned char* state);
    void Round(unsigned char* state, unsigned char* key);
    void FinalRound(unsigned char* state, unsigned char* key);
    bool EncryptAESBlock(bool encrypt_key, unsigned char* msg, unsigned char* enc_msg);

    SSL*     m_ssl;
    SSL_CTX* m_ctx;

    /* sock -> rd_crypt_buf -> rbio -> SSL -> rd_buf -> IN */
    /* sock -> rd_buf -> rbio -> SSL -> IN */
    BIO*        m_rbio;

    /* sock <- wr_crypt_buf <- wbio <- SSL <- wr_buf <- OUT */
    /* sock <- wr_buf <- wbio <- SSL <- OUT */
    BIO*        m_wbio;

    std::vector<unsigned char> m_enc_key;
    std::vector<unsigned char> m_enc_key_expanded;
    std::vector<unsigned char> m_enc_iv;
    std::vector<unsigned char> m_enc_mac;

    std::vector<unsigned char> m_dec_key;
    std::vector<unsigned char> m_dec_key_expanded;
    std::vector<unsigned char> m_dec_iv;
    std::vector<unsigned char> m_dec_mac;

    std::vector<unsigned char> m_master_key;

    int m_retrial_no;
    int m_key_len;
    int m_round_no;

    boost::mutex m_mutex;
    boost::condition_variable m_cond;
};

#endif // _SSL_CLIENT_HPP__

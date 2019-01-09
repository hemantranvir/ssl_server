#include <boost/thread.hpp>
#include <iostream>
#include "ssl_client.hpp"
#include "ssl_functions.h"
#include "ssl_constants.hpp"

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

SSLClient::SSLClient(int retrial_no)
    : m_ctx(nullptr)
    , m_ssl(nullptr)
    , m_rbio(nullptr)
    , m_wbio(nullptr)
    , m_retrial_no(retrial_no)
    , m_key_len(0)
    , m_round_no(0)
{
}

SSLClient::SSLClient()
    : m_ctx(nullptr)
    , m_ssl(nullptr)
    , m_rbio(nullptr)
    , m_wbio(nullptr)
    , m_retrial_no(5)
    , m_key_len(0)
    , m_round_no(0)
{
}

SSLClient::~SSLClient(void)
{
    if (m_ssl) {
        SSL_free(m_ssl);
    }
    if (m_ctx) {
        SSL_CTX_free(m_ctx);
    }
}

SSLHandler::SSLStatus SSLClient::InitSSLClient(const std::string& cadir, const std::string& cipher_name)
{
    boost::mutex::scoped_lock lock(m_mutex);
    SSL_load_error_strings(); //always success
    SSL_library_init();       //always success

    // Only TLS v1.2 is enable.
    m_ctx = SSL_CTX_new(TLS_client_method());
    if (!m_ctx) {
        return SSLHandler::kSSLCTXNewFail;
    }

    long ret_set_opt;
    ret_set_opt = SSL_CTX_set_options(m_ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2|SSL_OP_NO_TLSv1|SSL_OP_NO_TLSv1_1|SSL_OP_NO_TLSv1_3);

    m_rbio = BIO_new(BIO_s_mem());
    if (!m_rbio) {
        return SSLHandler::kSSLBIONewFail;
    }
    m_wbio = BIO_new(BIO_s_mem());
    if (!m_wbio) {
        return SSLHandler::kSSLBIONewFail;
    }
    m_ssl  = SSL_new(m_ctx);
    if (!m_ssl) {
        return SSLHandler::kSSLNewFail;
    }

    SSL_set_connect_state(m_ssl);        //always success
    SSL_set_bio(m_ssl, m_rbio, m_wbio);  //always success

    const char* p_cadir = cadir.c_str();
    const char* p_cipher_name = cipher_name.c_str();

    if (!SSL_CTX_load_verify_locations(m_ctx, NULL, p_cadir)) {
#ifdef DEBUG
        std::cout << "[SSLClient] " << "SSL CTX Verify Locations failed" << std::endl;
#endif
        return SSLHandler::kSSLCTXVerifyLocationsFail;
    }
    if (!SSL_CTX_set_cipher_list(m_ctx, p_cipher_name)) {
#ifdef DEBUG
        std::cout << "[SSLClient] " << "SSL CTX Set Cipher List failed" << std::endl;
#endif
        return SSLHandler::kSSLCTXSetCipherFail;
    }

    return SSLHandler::kSSLSuccess;
}

bool SSLClient::KickHandShake(std::string& msg)
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
    } while (ssl_error == SSL_ERROR_SSL && count > 0);

    return ssl_error != SSL_ERROR_SSL;
}

SSLHandler::SSLStatus SSLClient::Wait(int timeout)
{
    boost::system_time timeout_time(boost::posix_time::microsec_clock::universal_time() + boost::posix_time::milliseconds(timeout));
    boost::mutex::scoped_lock lock(m_mutex);
    // Need to wait until handshake is done.
    bool result = true;
    while ((result = m_cond.timed_wait(lock, timeout_time)) && !IsHandShakeDone());
    if (!result) {
        return SSLHandler::kSSLWaitFail;
    }

    if (SSL_get_verify_result(m_ssl) == X509_V_OK ) {
#ifdef DEBUG
        std::cout << "SSL verification OK" << std::endl;
#endif
    } else {
#ifdef DEBUG
        std::cout << "SSL verification NG" << std::endl;
#endif
        return SSLHandler::kSSLServerCertificateFail;
    }

    return SSLHandler::kSSLSuccess;
}

SSLHandler::SSLStatus SSLClient::EncryptSSL(std::string& msg)
{
    if (!IsHandShakeDone()) {
        return SSLHandler::kSSLHandShakeInProgress;
    } else {
        if (!WriteEncryptSSL(msg)) {
#ifdef DEBUG
            std::cout << "[SSLClient] " << "WriteEncryptSSL failed" << std::endl;
#endif
            return SSLHandler::kSSLWriteEncryptSSLFail;
        }
        if (!ReadEncryptBIO(msg)) {
#ifdef DEBUG
            std::cout << "[SSLClient] " << "ReadEncryptBIO failed" << std::endl;
#endif
            return SSLHandler::kSSLReadEncryptBIOFail;
        }
        return SSLHandler::kSSLSuccess;
    }
}

SSLHandler::SSLStatus SSLClient::DecryptSSL(std::string& in_msg, std::string& out_msg)
{
    boost::mutex::scoped_lock lock(m_mutex);
    out_msg.clear();

    if (!WriteDecryptBIO(in_msg)) {
#ifdef DEBUG
        std::cout << "[SSLClient] " << "WriteDecryptBIO failed" << std::endl;
#endif
        return SSLHandler::kSSLWriteDecryptBIOFail;
    }

    if (!IsHandShakeDone()) {
        if (!KickHandShake(out_msg)) {
            return SSLHandler::kSSLKickHandShakeFail;
        }
        //char buf[1024];
        //SSL_CIPHER_description(SSL_get_current_cipher(m_ssl), buf, sizeof(buf));
        //std::cout << "[ConnectSSL] Current cipher: " << buf << std::endl;

        if (IsHandShakeDone()) {
            m_cond.notify_all();
            return SSLHandler::kSSLHandShakeDone;
        }
        return SSLHandler::kSSLHandShakeInProgress;
    } else {
        if (!ReadDecryptSSL(in_msg)) {
#ifdef DEBUG
            std::cout << "[SSLClient] " << "ReadDecryptSSL failed" << std::endl;
#endif
            return SSLHandler::kSSLReadDecryptSSLFail;
        }
    }

    return SSLHandler::kSSLSuccess;
}

bool SSLClient::GetMasterSecret(std::vector<unsigned char>& key)
{
    if (m_master_key.empty()) {
        if (!FetchMasterSecret()) return false;
    }

    key.resize(m_master_key.size());
    key = m_master_key;

    return true;
}

bool SSLClient::GetReceiveSecrets(std::vector<unsigned char>& rx_iv, std::vector<unsigned char>& rx_key, std::vector<unsigned char>& rx_mac)
{
    if (m_dec_key.empty()) {
        if (!FetchReceiveSecrets()) return false;
    }

    rx_iv.resize(m_dec_iv.size());
    rx_iv = m_dec_iv;

    rx_key.resize(m_dec_key.size());
    rx_key = m_dec_key;

    rx_mac.resize(m_dec_mac.size());
    rx_mac = m_dec_mac;

    return true;
}

bool SSLClient::GetTransmitSecrets(std::vector<unsigned char>& tx_iv, std::vector<unsigned char>& tx_key, std::vector<unsigned char>& tx_mac)
{
    if (m_enc_key.empty()) {
        if (!FetchTransmitSecrets()) return false;
    }

    tx_iv.resize(m_enc_iv.size());
    tx_iv = m_enc_iv;

    tx_key.resize(m_enc_key.size());
    tx_key = m_enc_key;

    tx_mac.resize(m_enc_mac.size());
    tx_mac = m_enc_mac;

    return true;
}

bool SSLClient::GetCipherName(std::string& cipher_name)
{
    const char* name = SSL_get_cipher_name(m_ssl);
    if (name) {
        cipher_name = std::string(name);
        return true;
    } else {
        return false;
    }
}

bool SSLClient::GetEncryptExpandedKey(std::vector<unsigned char>& expanded_key)
{
    if (m_enc_key.empty()) {
        if (!FetchTransmitSecrets()) return false;
    }

    if (m_enc_key_expanded.empty()) {
        KeyExpansion(m_enc_key, m_enc_key_expanded);
    }

    expanded_key.resize(m_enc_key_expanded.size());
    expanded_key = m_enc_key_expanded;

    return true;
}

bool SSLClient::GetDecryptExpandedKey(std::vector<unsigned char>& expanded_key)
{
    if (m_dec_key.empty()) {
        if (!FetchReceiveSecrets()) return false;
    }

    if (m_dec_key_expanded.empty()) {
        KeyExpansion(m_dec_key, m_dec_key_expanded);
    }

    expanded_key.resize(m_dec_key_expanded.size());
    expanded_key = m_dec_key_expanded;

    return true;
}

// The AES encryption function
bool SSLClient::EncryptAES(bool encrypt_key, std::vector<unsigned char>& msg, std::vector<unsigned char>& enc_msg)
{
    if (msg.empty()) return false;

    if (encrypt_key && m_enc_key.empty()) {
        if (!FetchTransmitSecrets()) return false;
    } else if (!encrypt_key && m_dec_key.empty()) {
        if (!FetchReceiveSecrets()) return false;
    }
 
    if (encrypt_key && m_enc_key_expanded.empty()) {
        KeyExpansion(m_enc_key, m_enc_key_expanded);
    } else if (!encrypt_key && m_dec_key_expanded.empty()) {
        KeyExpansion(m_dec_key, m_dec_key_expanded);
    }

    int remainder = msg.size()%16;
    if (remainder != 0) {
        for (size_t i=0; i<16-remainder; i++) {
            msg.push_back(0);
        }
    }

    int len = msg.size();
    enc_msg.resize(len);

    for (size_t i=0; i<len; i=i+16) {
        EncryptAESBlock(encrypt_key, &msg[i], &enc_msg[i]);
    }

    return true;
}

bool SSLClient::IsHandShakeDone(void)
{
    if (m_ssl) {
        return SSL_is_init_finished(m_ssl) == 1;
    }
    else {
        return false;
    }
}

bool SSLClient::IsSSLerror(int ret)
{
    return (ret == SSL_ERROR_ZERO_RETURN
         || ret == SSL_ERROR_SYSCALL
         || ret == SSL_ERROR_SSL );
}

bool SSLClient::WriteEncryptSSL(const std::string& msg)
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

bool SSLClient::ReadEncryptBIO(std::string& msg)
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
#ifdef DEBUG
            std::cout << "[SSLClient] " << "No Encrypted message to send" << std::endl;
#endif
            return false;
        }
        for (int i=0; i<n; ++i) {
            msg += buf[i];
        }
    } while (n > 0);

    return true;
}

bool SSLClient::WriteDecryptBIO(const std::string& msg)
{
    const char* buf = msg.c_str();
    int len = msg.length();
    int n;

    if (len <= 0 || m_rbio == nullptr) {
#ifdef DEBUG
        std::cout << "[SSLClient] " << "WriteDecryptBIO len <=0 or m_rbio is null" << std::endl;
#endif
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

bool SSLClient::ReadDecryptSSL(std::string& msg)
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
#ifdef DEBUG
            std::cout << "[SSLClient] " << "SSL_read failed, n: " << n  << ", SSL_get_error: " << ret << std::endl;
#endif
            return false;
        }
        for (int i=0; i<n; ++i) {
            msg += buf[i];
        }
    } while (n > 0);

    return true;
}

bool SSLClient::FetchMasterSecret()
{
    int key_len = FetchMasterKeyLength(m_ssl);
    if (key_len > 0) {
        m_master_key.resize(key_len);
        if (FetchMasterKey(m_ssl, &m_master_key[0]) != 0) return false;
    } else {
        m_master_key.clear();
    }
    return true;
}

bool SSLClient::FetchReceiveSecrets()
{
    int iv_len  = FetchReceiveIVLength(m_ssl);
    int key_len = FetchReceiveKeyLength(m_ssl);
    int mac_len = FetchReceiveMacLength(m_ssl);
    if (iv_len > 0) {
        m_dec_iv.resize(iv_len);
        if (FetchReceiveIV(m_ssl, &m_dec_iv[0]) != 0) return false;
    } else {
        m_dec_iv.clear();
    }
    if (key_len > 0) {
        m_dec_key.resize(key_len);
        if (FetchReceiveKey(m_ssl, &m_dec_key[0]) != 0) return false;
        if (key_len == 32) {
            MixColumns(&m_dec_key[16]);
        }
    } else {
        m_dec_key.clear();
    }
    if (mac_len > 0) {
        m_dec_mac.resize(mac_len);
        if (FetchReceiveMac(m_ssl, &m_dec_mac[0]) != 0) return false;
    } else {
        m_dec_mac.clear();
    }

    return true;
}

bool SSLClient::FetchTransmitSecrets()
{
    int iv_len  = FetchTransmitIVLength(m_ssl);
    int key_len = FetchTransmitKeyLength(m_ssl);
    int mac_len = FetchTransmitMacLength(m_ssl);
    if (iv_len > 0) {
        m_enc_iv.resize(iv_len);
        if (FetchTransmitIV(m_ssl, &m_enc_iv[0]) != 0) return false;
    } else {
        m_enc_iv.clear();
    }
    if (key_len > 0) {
        m_enc_key.resize(key_len);
        if (FetchTransmitKey(m_ssl, &m_enc_key[0]) != 0) return false;
    } else {
        m_enc_key.clear();
    }
    if (mac_len > 0) {
        m_enc_mac.resize(mac_len);
        if (FetchTransmitMac(m_ssl, &m_enc_mac[0]) != 0) return false;
    } else {
        m_enc_mac.clear();
    }

    return true;
}

void SSLClient::KeyExpansionCore(std::vector<unsigned char>& in, int round_no)
{
    // Rotate left by one byte: shift left
    unsigned char t = in[0];
    in[0] = in[1];
    in[1] = in[2];
    in[2] = in[3];
    in[3] = t;

    // S-box 4 bytes
    in[0] = s_box[in[0]];
    in[1] = s_box[in[1]];
    in[2] = s_box[in[2]];
    in[3] = s_box[in[3]];

    // RCon
    in[0] ^= rcon[round_no];
}

void  SSLClient::KeyExpansion(const std::vector<unsigned char>& input_key, std::vector<unsigned char>& expanded_keys)
{
    m_key_len = input_key.size();
    if (m_key_len == 16) {
        m_round_no = 10;
    } else if (m_key_len == 32) {
        m_round_no = 14;
    }

    int bytes_to_generate = 16*(m_round_no+1);
    expanded_keys.resize(bytes_to_generate);

    // The first 128 bits are the original key
    for (int i = 0; i < m_key_len; i++) {
        expanded_keys[i] = input_key[i];
    }

    int bytes_generated = m_key_len; // Bytes we've generated so far
    int rcon_iteration = 1; // Keeps track of rcon value
    std::vector<unsigned char> tmp_core; // Temp storage for core
    tmp_core.resize(4);

    while (bytes_generated < bytes_to_generate) {
        // Read 4 bytes for the core
        // They are the previously generated 4 bytes
        // Initially, these will be the final 4 bytes of the original key
        //
        for (int i = 0; i < 4; i++) {
            tmp_core[i] = expanded_keys[i + bytes_generated - 4];
        }

        // Perform the core once for each 16 byte key
        if (bytes_generated % m_key_len == 0) {
            KeyExpansionCore(tmp_core, rcon_iteration++);

        } else if (m_key_len > 24 && bytes_generated % m_key_len == 16) {
            tmp_core[0] = s_box[tmp_core[0]];
            tmp_core[1] = s_box[tmp_core[1]];
            tmp_core[2] = s_box[tmp_core[2]];
            tmp_core[3] = s_box[tmp_core[3]];

        }

        for (unsigned char a = 0; a < 4; a++) {
            expanded_keys[bytes_generated] = expanded_keys[bytes_generated - m_key_len] ^ tmp_core[a];
            bytes_generated++;
        }
    }
}

// Serves as the initial round during encryption
// AddRoundKey is simply an XOR of a 128-bit block with the 128-bit key.
void SSLClient::AddRoundKey(unsigned char * state, unsigned char * round_key) {
    for (int i = 0; i < 16; i++) {
       	state[i] ^= round_key[i];
    }
}

// Perform substitution to each of the 16 bytes
// Uses S-box as lookup table
void SSLClient::SubBytes(unsigned char * state) {
    for (int i = 0; i < 16; i++) {
       	state[i] = s_box[state[i]];
    }
}

// Shift left, adds diffusion
void SSLClient::ShiftRows(unsigned char * state) {
    unsigned char tmp[16];

    // Column 1
    tmp[0] = state[0];
    tmp[1] = state[5];
    tmp[2] = state[10];
    tmp[3] = state[15];

    // Column 2
    tmp[4] = state[4];
    tmp[5] = state[9];
    tmp[6] = state[14];
    tmp[7] = state[3];

    // Column 3
    tmp[8] = state[8];
    tmp[9] = state[13];
    tmp[10] = state[2];
    tmp[11] = state[7];

    // Column 4
    tmp[12] = state[12];
    tmp[13] = state[1];
    tmp[14] = state[6];
    tmp[15] = state[11];

    for (int i = 0; i < 16; i++) {
        state[i] = tmp[i];
    }
}

// MixColumns uses mul2, mul3 look-up tables
// Source of diffusion
void SSLClient::MixColumns(unsigned char * state) {
    unsigned char tmp[16];

    tmp[0] = (unsigned char) mul2[state[0]] ^ mul3[state[1]] ^ state[2] ^ state[3];
    tmp[1] = (unsigned char) state[0] ^ mul2[state[1]] ^ mul3[state[2]] ^ state[3];
    tmp[2] = (unsigned char) state[0] ^ state[1] ^ mul2[state[2]] ^ mul3[state[3]];
    tmp[3] = (unsigned char) mul3[state[0]] ^ state[1] ^ state[2] ^ mul2[state[3]];

    tmp[4] = (unsigned char)mul2[state[4]] ^ mul3[state[5]] ^ state[6] ^ state[7];
    tmp[5] = (unsigned char)state[4] ^ mul2[state[5]] ^ mul3[state[6]] ^ state[7];
    tmp[6] = (unsigned char)state[4] ^ state[5] ^ mul2[state[6]] ^ mul3[state[7]];
    tmp[7] = (unsigned char)mul3[state[4]] ^ state[5] ^ state[6] ^ mul2[state[7]];

    tmp[8] = (unsigned char)mul2[state[8]] ^ mul3[state[9]] ^ state[10] ^ state[11];
    tmp[9] = (unsigned char)state[8] ^ mul2[state[9]] ^ mul3[state[10]] ^ state[11];
    tmp[10] = (unsigned char)state[8] ^ state[9] ^ mul2[state[10]] ^ mul3[state[11]];
    tmp[11] = (unsigned char)mul3[state[8]] ^ state[9] ^ state[10] ^ mul2[state[11]];

    tmp[12] = (unsigned char)mul2[state[12]] ^ mul3[state[13]] ^ state[14] ^ state[15];
    tmp[13] = (unsigned char)state[12] ^ mul2[state[13]] ^ mul3[state[14]] ^ state[15];
    tmp[14] = (unsigned char)state[12] ^ state[13] ^ mul2[state[14]] ^ mul3[state[15]];
    tmp[15] = (unsigned char)mul3[state[12]] ^ state[13] ^ state[14] ^ mul2[state[15]];

    for (int i = 0; i < 16; i++) {
        state[i] = tmp[i];
    }
}

// Each round operates on 128 bits at a time
// The number of rounds is defined in AESEncrypt()
void SSLClient::Round(unsigned char * state, unsigned char * key) {
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, key);
}

// Same as Round() except it doesn't mix columns
void SSLClient::FinalRound(unsigned char * state, unsigned char * key) {
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, key);
}

// The AES encryption function which works on 128 bit data
// Organizes the confusion and diffusion steps into one function
bool SSLClient::EncryptAESBlock(bool encrypt_key, unsigned char* msg, unsigned char* enc_msg)
{
    unsigned char* expanded_key;

    if (encrypt_key) {
        expanded_key = &m_enc_key_expanded[0];
    } else {
        expanded_key = &m_dec_key_expanded[0];
    }

    unsigned char state[16]; // Stores the first 16 bytes of original message

    for (int i = 0; i < 16; i++) {
        state[i] = msg[i];
    }

    AddRoundKey(state, expanded_key); // Initial round

    for (int i = 0; i < m_round_no-1; i++) {
        Round(state, expanded_key + (16 * (i+1)));
    }

    FinalRound(state, expanded_key + (16*(m_round_no)));

    // Copy encrypted state to buffer
    for (int i = 0; i < 16; i++) {
        enc_msg[i] = state[i];
    }

    return true;
}

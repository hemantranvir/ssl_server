#ifndef _SSL_CIPHER_HPP__
#define _SSL_CIPHER_HPP__

#include <boost/thread.hpp>
#include <string>
#include <boost/asio.hpp>

class SSLCipher
{
public:
    SSLCipher();
    virtual ~SSLCipher(void);

    void SetMasterSecret(const std::vector<unsigned char>& key);
    void SetReceiveSecrets(const std::vector<unsigned char>& rx_iv, const std::vector<unsigned char>& rx_key, const std::vector<unsigned char>& rx_mac);
    void SetTransmitSecrets(const std::vector<unsigned char>& tx_iv, const std::vector<unsigned char>& tx_key, const std::vector<unsigned char>& tx_mac);

    //Encrypt and Decrypt Functions for only AES128-SHA and AES256-SHA cipher suite (does not support other cipher suites)
    bool DecryptMsgAESCBC(std::string& recv_msg);
    bool EncryptMsgAESCBC(std::string& send_msg, const std::string& ssl_msg);

private:

    bool KeyExpansionCore(std::vector<unsigned char>& in, int round_no);
    bool KeyExpansion(const std::vector<unsigned char>& input_key, std::vector<unsigned char>& expanded_keys);

    void InverseAddRoundKey(unsigned char* state, unsigned char* round_key);
    void InverseMixColumns(unsigned char* state);
    void InverseShiftRows(unsigned char* state);
    void InverseSubBytes(unsigned char* state);
    void InverseRound(unsigned char* state, unsigned char* key);
    void InverseInitialRound(unsigned char* state, unsigned char* key);
    bool DecryptAESCBC(unsigned char* enc_msg, unsigned char* expanded_key, unsigned char* dec_msg);

    void AddRoundKey(unsigned char* state, unsigned char* round_key);
    void MixColumns(unsigned char* state);
    void ShiftRows(unsigned char* state);
    void SubBytes(unsigned char* state);
    void Round(unsigned char* state, unsigned char* key);
    void FinalRound(unsigned char* state, unsigned char* key);
    bool EncryptAESCBC(unsigned char* msg, unsigned char* expanded_key, unsigned char* enc_msg);

    std::vector<unsigned char> m_enc_key;
    std::vector<unsigned char> m_enc_key_expanded;
    std::vector<unsigned char> m_enc_iv;
    std::vector<unsigned char> m_enc_mac;

    std::vector<unsigned char> m_dec_key;
    std::vector<unsigned char> m_dec_key_expanded;
    std::vector<unsigned char> m_dec_iv;
    std::vector<unsigned char> m_dec_mac;

    std::vector<unsigned char> m_master_key;

    int m_key_len;
    int m_round_no;
};

#endif // _SSL_CIPHER_HPP__


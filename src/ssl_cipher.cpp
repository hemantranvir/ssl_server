#include <boost/thread.hpp>
#include <iostream>
#include "ssl_cipher.hpp"
#include "cipher_constants.hpp"

#define MAX_BUF_SIZE 2048

SSLCipher::SSLCipher()
    : m_key_len(0)
    , m_round_no(0)
{
}

SSLCipher::~SSLCipher(void)
{
}

void SSLCipher::SetMasterSecret(const std::vector<unsigned char>& key)
{
    m_master_key = key;
}

void SSLCipher::SetReceiveSecrets(const std::vector<unsigned char>& rx_iv, const std::vector<unsigned char>& rx_key, const std::vector<unsigned char>& rx_mac)
{
    m_dec_iv  = rx_iv;
    m_dec_key = rx_key;
    m_dec_mac = rx_mac;
}

void SSLCipher::SetTransmitSecrets(const std::vector<unsigned char>& tx_iv, const std::vector<unsigned char>& tx_key, const std::vector<unsigned char>& tx_mac)
{
    m_enc_iv  = tx_iv;
    m_enc_key = tx_key;
    m_enc_mac = tx_mac;
}

//Decrypt Msg for AES CBC (only TLSv1.3 is supported)
bool SSLCipher::DecryptMsgAESCBC(std::string& recv_msg)
{
    if (m_dec_key_expanded.empty()) {
        KeyExpansion(m_dec_key, m_dec_key_expanded);
    }

#ifdef DEBUG
    std::cout << "[SSLCipher]" << "Received message in hex:" << std::endl;
    for (int i=0; i<recv_msg.size(); i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)((unsigned char)recv_msg[i]);
        std::cout << " ";
    }
    std::cout << std::endl;
#endif

    int len = ((uint8_t)recv_msg[3] << 8 | (uint8_t)recv_msg[4]) - 20;
#ifdef DEBUG
    std::cout << "[SSLCipher] " << "len is: " << std::dec << len << std::endl;
#endif
    std::vector<unsigned char> enc_msg(recv_msg.begin()+5, recv_msg.begin()+5+(len));
 
    // len will always be multiples of 16
    len = enc_msg.size();
    std::vector<unsigned char> dec_msg;
    dec_msg.resize(len);

    for (int i = 0; i < len; i += 16) {
        DecryptAESCBC(&enc_msg[0+i], &m_dec_key_expanded[0], &dec_msg[0+i]);
    }
 
    // XOR with 16 bytes of IV saved and rest XOR with the received message
    for (int i = 0; i < 16; i ++) {
        dec_msg[i] ^= m_dec_iv[i];
    }
    for (int i = 16; i < len; i++) {
        dec_msg[i] ^= enc_msg[i-16];
    }

    //Saving 16 bytes of IV for next message
    for (int i = 0; i < 16; i++) {
        m_dec_iv[i] = enc_msg[len-16+i];
    }
 
#ifdef DEBUG
    std::cout << "[SSLCipher]" << "Decrypted message in hex:" << std::endl;
    for (int i = 0; i < len; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)dec_msg[i];
        std::cout << " ";
    }
    std::cout << std::endl;
#endif

    //Remove the padding
    int end;
    unsigned char padding = dec_msg[len-1];
    for (int i = len-2; i > 15; i--) {
        if (dec_msg[i] != padding) {
            end = i+1;
            break;
        }
    }

    //Copy the decrypted message in string
    recv_msg = std::string(dec_msg.begin()+16, dec_msg.begin()+end);
    return true;
}

bool SSLCipher::EncryptMsgAESCBC(std::string& send_msg, const std::string& ssl_msg)
{
    if (m_enc_key_expanded.empty()) {
        KeyExpansion(m_enc_key, m_enc_key_expanded);
    }

    std::vector<unsigned char> msg(send_msg.begin(), send_msg.end());

    int remainder = msg.size()%16;
    if (remainder != 0) {
        for (size_t i=0; i<16-remainder; i++) {
            msg.push_back((unsigned char)16-remainder-1);
        }
    } else {
        for (size_t i=0; i<16-remainder; i++) {
            msg.push_back((unsigned char)16-remainder-1);
        }
    }

    int len = msg.size();
    std::vector<unsigned char> enc_msg;
    enc_msg.resize(len);

    // XOR with 16 bytes of IV from ssl message and rest XOR with the encrypted message
    for (int i = 0; i < 16; i ++) {
        msg[i] ^= ((unsigned char)ssl_msg[i+5]);
    }

    for (int i = 0; i < len; i += 16) {
       if (i>0) {
            for (int j = i; j < i+16; j++) {
                msg[j] ^= enc_msg[j-16];
            }
        }
        EncryptAESCBC(&msg[0+i], &m_enc_key_expanded[0], &enc_msg[0+i]);
    }
 
#ifdef DEBUG
    std::cout << "[SSLCipher]" << "Encrypted message in hex:" << std::endl;
    for (int i = 0; i < len; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)enc_msg[i];
        std::cout << " ";
    }
    std::cout << std::endl;
#endif

    //Adding the last 20 bytes(mac) from ssl message
    enc_msg.insert(enc_msg.end(), ssl_msg.end()-20, ssl_msg.end());
    //Extracting and adding the 5 bytes header and 16 bytes of explicit IV from ssl message
    std::vector<unsigned char> tmp(ssl_msg.begin(), ssl_msg.begin()+21);
    tmp.insert(tmp.end(), enc_msg.begin(), enc_msg.end());
    //Copying the message to string
    send_msg = std::string(tmp.begin(), tmp.end());

    return true;
}

bool SSLCipher::KeyExpansionCore(std::vector<unsigned char>& in, int round_no)
{
    // Rotate left by one byte: shift left 
    unsigned char t = in[0];
    in[0] = in[1];
    in[1] = in[2];
    in[2] = in[3];
    in[3] = t;

    // S-box 4 bytes 
    in[0] = box[in[0]];
    in[1] = box[in[1]];
    in[2] = box[in[2]];
    in[3] = box[in[3]];

    // RCon
    in[0] ^= round_con[round_no];
}

bool SSLCipher::KeyExpansion(const std::vector<unsigned char>& input_key, std::vector<unsigned char>& expanded_keys)
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
    int round_con_iteration = 1; // Keeps track of round_con value
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
            KeyExpansionCore(tmp_core, round_con_iteration++);

        } else if (m_key_len > 24 && bytes_generated % m_key_len == 16) {
            tmp_core[0] = box[tmp_core[0]];
            tmp_core[1] = box[tmp_core[1]];
            tmp_core[2] = box[tmp_core[2]];
            tmp_core[3] = box[tmp_core[3]];

        }

        for (unsigned char a = 0; a < 4; a++) {
            expanded_keys[bytes_generated] = expanded_keys[bytes_generated - m_key_len] ^ tmp_core[a];
            bytes_generated++;
        }
    }
}

// Used in Round() and serves as the final round during decryption
// SubRoundKey is simply an XOR of a 128-bit block with the 128-bit key.
// So basically does the same as AddRoundKey in the encryption
void SSLCipher::InverseAddRoundKey(unsigned char* state, unsigned char* round_key) {
    for (int i = 0; i < 16; i++) {
        state[i] ^= round_key[i];
    }
}

// InverseMixColumns uses mult9, mult11, mult13, mult14 look-up tables
// Unmixes the columns by reversing the effect of MixColumns in encryption
void SSLCipher::InverseMixColumns(unsigned char* state) {
    unsigned char tmp[16];

    tmp[0] = (unsigned char)mult14[state[0]] ^ mult11[state[1]] ^ mult13[state[2]] ^ mult9[state[3]];
    tmp[1] = (unsigned char)mult9[state[0]] ^ mult14[state[1]] ^ mult11[state[2]] ^ mult13[state[3]];
    tmp[2] = (unsigned char)mult13[state[0]] ^ mult9[state[1]] ^ mult14[state[2]] ^ mult11[state[3]];
    tmp[3] = (unsigned char)mult11[state[0]] ^ mult13[state[1]] ^ mult9[state[2]] ^ mult14[state[3]];

    tmp[4] = (unsigned char)mult14[state[4]] ^ mult11[state[5]] ^ mult13[state[6]] ^ mult9[state[7]];
    tmp[5] = (unsigned char)mult9[state[4]] ^ mult14[state[5]] ^ mult11[state[6]] ^ mult13[state[7]];
    tmp[6] = (unsigned char)mult13[state[4]] ^ mult9[state[5]] ^ mult14[state[6]] ^ mult11[state[7]];
    tmp[7] = (unsigned char)mult11[state[4]] ^ mult13[state[5]] ^ mult9[state[6]] ^ mult14[state[7]];

    tmp[8] = (unsigned char)mult14[state[8]] ^ mult11[state[9]] ^ mult13[state[10]] ^ mult9[state[11]];
    tmp[9] = (unsigned char)mult9[state[8]] ^ mult14[state[9]] ^ mult11[state[10]] ^ mult13[state[11]];
    tmp[10] = (unsigned char)mult13[state[8]] ^ mult9[state[9]] ^ mult14[state[10]] ^ mult11[state[11]];
    tmp[11] = (unsigned char)mult11[state[8]] ^ mult13[state[9]] ^ mult9[state[10]] ^ mult14[state[11]];

    tmp[12] = (unsigned char)mult14[state[12]] ^ mult11[state[13]] ^ mult13[state[14]] ^ mult9[state[15]];
    tmp[13] = (unsigned char)mult9[state[12]] ^ mult14[state[13]] ^ mult11[state[14]] ^ mult13[state[15]];
    tmp[14] = (unsigned char)mult13[state[12]] ^ mult9[state[13]] ^ mult14[state[14]] ^ mult11[state[15]];
    tmp[15] = (unsigned char)mult11[state[12]] ^ mult13[state[13]] ^ mult9[state[14]] ^ mult14[state[15]];

    for (int i = 0; i < 16; i++) {
        state[i] = tmp[i];
    }
}

// Shifts rows right (rather than left) for decryption
void SSLCipher::InverseShiftRows(unsigned char* state) {
    unsigned char tmp[16];

    // Column 1
    tmp[0] = state[0];
    tmp[1] = state[13];
    tmp[2] = state[10];
    tmp[3] = state[7];

    // Column 2
    tmp[4] = state[4];
    tmp[5] = state[1];
    tmp[6] = state[14];
    tmp[7] = state[11];

    // Column 3
    tmp[8] = state[8];
    tmp[9] = state[5];
    tmp[10] = state[2];
    tmp[11] = state[15];

    // Column 4
    tmp[12] = state[12];
    tmp[13] = state[9];
    tmp[14] = state[6];
    tmp[15] = state[3];

    for (int i = 0; i < 16; i++) {
        state[i] = tmp[i];
    }
}

// Perform substitution to each of the 16 bytes
// Uses inverse S-box as lookup table
void SSLCipher::InverseSubBytes(unsigned char* state) {
    for (int i = 0; i < 16; i++) { 
        // Perform substitution to each of the 16 bytes
        state[i] = inv_box[state[i]];
    }
}

// Each round operates on 128 bits at a time
// The number of rounds is defined in AESDecrypt()
// Not surprisingly, the steps are the encryption steps but reversed
void SSLCipher::InverseRound(unsigned char* state, unsigned char* key) {
    InverseAddRoundKey(state, key);
    InverseMixColumns(state);
    InverseShiftRows(state);
    InverseSubBytes(state);
}

// Same as Round() but no InverseMixColumns
void SSLCipher::InverseInitialRound(unsigned char* state, unsigned char* key) {
    InverseAddRoundKey(state, key);
    InverseShiftRows(state);
    InverseSubBytes(state);
}

bool SSLCipher::DecryptAESCBC(unsigned char* enc_msg, unsigned char* expanded_key, unsigned char* dec_msg)
{
    unsigned char state[16]; // Stores the first 16 bytes of encrypted message

    for (int i = 0; i < 16; i++) {
        state[i] = enc_msg[i];
    }
    
    InverseInitialRound(state, expanded_key+(16*(m_round_no)));

    for (int i = m_round_no-2; i >= 0; i--) {
        InverseRound(state, expanded_key + (16 * (i + 1)));
    }

    InverseAddRoundKey(state, expanded_key); // Final round

    // Copy decrypted state to buffer
    for (int i = 0; i < 16; i++) {
        dec_msg[i] = state[i];
    }
}

// Serves as the initial round during encryption
// AddRoundKey is simply an XOR of a 128-bit block with the 128-bit key.
void SSLCipher::AddRoundKey(unsigned char * state, unsigned char * round_key) {
    for (int i = 0; i < 16; i++) {
       	state[i] ^= round_key[i];
    }
}

// Perform substitution to each of the 16 bytes
// Uses S-box as lookup table 
void SSLCipher::SubBytes(unsigned char * state) {
    for (int i = 0; i < 16; i++) {
       	state[i] = box[state[i]];
    }
}

// Shift left, adds diffusion
void SSLCipher::ShiftRows(unsigned char * state) {
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

// MixColumns uses mult2, mult3 look-up tables
// Source of diffusion
void SSLCipher::MixColumns(unsigned char * state) {
    unsigned char tmp[16];

    tmp[0] = (unsigned char) mult2[state[0]] ^ mult3[state[1]] ^ state[2] ^ state[3];
    tmp[1] = (unsigned char) state[0] ^ mult2[state[1]] ^ mult3[state[2]] ^ state[3];
    tmp[2] = (unsigned char) state[0] ^ state[1] ^ mult2[state[2]] ^ mult3[state[3]];
    tmp[3] = (unsigned char) mult3[state[0]] ^ state[1] ^ state[2] ^ mult2[state[3]];

    tmp[4] = (unsigned char)mult2[state[4]] ^ mult3[state[5]] ^ state[6] ^ state[7];
    tmp[5] = (unsigned char)state[4] ^ mult2[state[5]] ^ mult3[state[6]] ^ state[7];
    tmp[6] = (unsigned char)state[4] ^ state[5] ^ mult2[state[6]] ^ mult3[state[7]];
    tmp[7] = (unsigned char)mult3[state[4]] ^ state[5] ^ state[6] ^ mult2[state[7]];

    tmp[8] = (unsigned char)mult2[state[8]] ^ mult3[state[9]] ^ state[10] ^ state[11];
    tmp[9] = (unsigned char)state[8] ^ mult2[state[9]] ^ mult3[state[10]] ^ state[11];
    tmp[10] = (unsigned char)state[8] ^ state[9] ^ mult2[state[10]] ^ mult3[state[11]];
    tmp[11] = (unsigned char)mult3[state[8]] ^ state[9] ^ state[10] ^ mult2[state[11]];

    tmp[12] = (unsigned char)mult2[state[12]] ^ mult3[state[13]] ^ state[14] ^ state[15];
    tmp[13] = (unsigned char)state[12] ^ mult2[state[13]] ^ mult3[state[14]] ^ state[15];
    tmp[14] = (unsigned char)state[12] ^ state[13] ^ mult2[state[14]] ^ mult3[state[15]];
    tmp[15] = (unsigned char)mult3[state[12]] ^ state[13] ^ state[14] ^ mult2[state[15]];

    for (int i = 0; i < 16; i++) {
        state[i] = tmp[i];
    }
}

// Each round operates on 128 bits at a time
// The number of rounds is defined in AESEncrypt()
void SSLCipher::Round(unsigned char * state, unsigned char * key) {
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, key);
}

// Same as Round() except it doesn't mix columns
void SSLCipher::FinalRound(unsigned char * state, unsigned char * key) {
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, key);
}

// The AES encryption function
// Organizes the confusion and diffusion steps into one function
bool SSLCipher::EncryptAESCBC(unsigned char * msg, unsigned char* expanded_key, unsigned char * enc_msg)
{
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
}

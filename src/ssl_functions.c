#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/modes.h>
#include "ssl/ssl_locl.h"
#include "crypto/evp/evp_locl.h"
#include "crypto/include/internal/evp_int.h"
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <inttypes.h>
#include "ssl_functions.h"

//Copied from crypto/evp/e_aes.c
typedef struct {
    union {
        double align;
        AES_KEY ks;
    } ks;
    block128_f block;
    union {
        cbc128_f cbc;
        ctr128_f ctr;
    } stream;
} EVP_AES_KEY;

int FetchMasterKeyLength(SSL* ssl)
{
    unsigned char master_key[1024];
    memset(master_key, 0x00, sizeof(master_key));
    int master_key_len;
    if (!ssl || !ssl->session) return -1;

    master_key_len = SSL_SESSION_get_master_key(ssl->session, master_key, 1024);
    return master_key_len;
}

int FetchMasterKey(SSL* ssl, unsigned char* key)
{
    if (!ssl || !ssl->session) return -1;

    SSL_SESSION_get_master_key(ssl->session, key, 1024);
    return 0;
}

int FetchReceiveIVLength(SSL* ssl)
{
    if (!ssl || !ssl->enc_read_ctx || !ssl->enc_read_ctx->cipher) return -1;

    return ssl->enc_read_ctx->cipher->iv_len;
}

int FetchReceiveKeyLength(SSL* ssl)
{
    if (!ssl || !ssl->enc_read_ctx || !ssl->enc_read_ctx->cipher) return -1;

    return (ssl->enc_read_ctx->cipher->key_len);
}

int FetchReceiveMacLength(SSL* ssl)
{
    if (!ssl || !ssl->s3) return -1;

    return ssl->s3->read_mac_secret_size;
}

int FetchReceiveIV(SSL* ssl, unsigned char* iv)
{
    int len = FetchReceiveIVLength(ssl);
    if (len <= 0 || !ssl || !ssl->enc_read_ctx || !ssl->enc_read_ctx->iv) return -1;

    memcpy(iv, ssl->enc_read_ctx->iv, len);
    return 0;
}

int FetchReceiveKey(SSL* ssl, unsigned char* key)
{
    int len;
    len = FetchReceiveKeyLength(ssl);
    if (len <= 0 || !ssl || !ssl->enc_read_ctx) return -1;

    EVP_AES_KEY *cipher_data;
    cipher_data = EVP_CIPHER_CTX_get_cipher_data(ssl->enc_read_ctx);
 
    if (!cipher_data || !cipher_data->ks.ks.rd_key) return -1;

    const char* cipher_name = SSL_get_cipher_name(ssl);
    int aes_cbc_on = 0;

    if (strcmp("AES128-SHA", cipher_name) == 0 || strcmp("AES128-SHA256", cipher_name) == 0
        || strcmp("AES256-SHA", cipher_name) == 0 || strcmp("AES256-SHA256", cipher_name) == 0) {
        aes_cbc_on = 1;
    }

    int offset;
    if (len == 16) {
        offset = 40;
    } else if (len == 32) {
        offset = 56;
    }

    int i;
    for (i=0; i<len/4; i++) {
        if (aes_cbc_on == 0) {
            key[4*i]   = cipher_data->ks.ks.rd_key[i] >> 24;
            key[4*i+1] = cipher_data->ks.ks.rd_key[i] >> 16;
            key[4*i+2] = cipher_data->ks.ks.rd_key[i] >> 8;
            key[4*i+3] = cipher_data->ks.ks.rd_key[i];
        } else {
            key[4*i]   = cipher_data->ks.ks.rd_key[offset+i - 8*(i/4)] >> 24;
            key[4*i+1] = cipher_data->ks.ks.rd_key[offset+i - 8*(i/4)] >> 16;
            key[4*i+2] = cipher_data->ks.ks.rd_key[offset+i - 8*(i/4)] >> 8;
            key[4*i+3] = cipher_data->ks.ks.rd_key[offset+i - 8*(i/4)];
        }
    }

    return 0;
}

int FetchReceiveMac(SSL* ssl, unsigned char* mac)
{
    int len = FetchReceiveMacLength(ssl); 
    if (len <= 0 || !ssl || !ssl->s3 || !ssl->s3->read_mac_secret) return -1;

    memcpy(mac, ssl->s3->read_mac_secret, len);
    return 0;
}

int FetchTransmitIVLength(SSL* ssl)
{
    if (!ssl || !ssl->enc_write_ctx || !ssl->enc_write_ctx->cipher) return -1;

    return ssl->enc_write_ctx->cipher->iv_len;
}

int FetchTransmitKeyLength(SSL* ssl)
{
    if (!ssl || !ssl->enc_write_ctx || !ssl->enc_write_ctx->cipher) return -1;

    return (ssl->enc_write_ctx->cipher->key_len);
}

int FetchTransmitMacLength(SSL* ssl)
{
    if (!ssl || !ssl->s3) return -1;

    return ssl->s3->write_mac_secret_size;
}

int FetchTransmitIV(SSL* ssl, unsigned char* iv)
{
    int len = FetchTransmitIVLength(ssl);
    if (len <= 0 || !ssl || !ssl->enc_write_ctx || !ssl->enc_write_ctx->iv) return -1;

    memcpy(iv, ssl->enc_write_ctx->iv, len);
    return 0;
}

int FetchTransmitKey(SSL* ssl, unsigned char* key)
{
    int len;
    len = FetchTransmitKeyLength(ssl);
    if (len <= 0 || !ssl || !ssl->enc_write_ctx) return -1;

    EVP_AES_KEY *cipher_data;
    cipher_data = EVP_CIPHER_CTX_get_cipher_data(ssl->enc_write_ctx);
    if (!cipher_data || !cipher_data->ks.ks.rd_key) return -1;

    //memcpy(key, cipher_data->ks.ks.rd_key, len);
    int i;
    for (i=0; i<len/4; i++) {
        key[4*i]   = cipher_data->ks.ks.rd_key[i] >> 24;
        key[4*i+1] = cipher_data->ks.ks.rd_key[i] >> 16;
        key[4*i+2] = cipher_data->ks.ks.rd_key[i] >> 8;
        key[4*i+3] = cipher_data->ks.ks.rd_key[i];
        //key[4*i]   = cipher_data->ks.ks.rd_key[40+i] >> 24;
        //key[4*i+1] = cipher_data->ks.ks.rd_key[40+i] >> 16;
        //key[4*i+2] = cipher_data->ks.ks.rd_key[40+i] >> 8;
        //key[4*i+3] = cipher_data->ks.ks.rd_key[40+i];
    }

    return 0;
}

int FetchTransmitMac(SSL* ssl, unsigned char* mac)
{
    int len = FetchTransmitMacLength(ssl); 
    if (len <= 0 || !ssl || !ssl->s3) return -1;

    memcpy(mac, ssl->s3->write_mac_secret, len);
    return 0;
}

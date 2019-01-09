#ifndef SSL_FUNCTIONS_H__
#define SSL_FUNCTIONS_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/ssl.h>
#include <openssl/ossl_typ.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/modes.h>

int FetchMasterKeyLength(SSL* ssl);
int FetchMasterKey(SSL* ssl, unsigned char* key);

int FetchReceiveIVLength(SSL* ssl);
int FetchReceiveKeyLength(SSL* ssl);
int FetchReceiveMacLength(SSL* ssl);
int FetchReceiveIV(SSL* ssl, unsigned char* iv);
int FetchReceiveKey(SSL* ssl, unsigned char* key);
int FetchReceiveMac(SSL* ssl, unsigned char* mac);

int FetchTransmitIVLength(SSL* ssl);
int FetchTransmitKeyLength(SSL* ssl);
int FetchTransmitMacLength(SSL* ssl);
int FetchTransmitIV(SSL* ssl, unsigned char* iv);
int FetchTransmitKey(SSL* ssl, unsigned char* key);
int FetchTransmitMac(SSL* ssl, unsigned char* mac);

#ifdef __cplusplus
}
#endif

#endif // SSL_FUNCTIONS_H__

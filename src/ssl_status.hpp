#ifndef _SSL_STATUS_HPP__
#define _SSL_STATUS_HPP__

#include <string>

namespace SSLHandler {

enum SSLStatus
{
    kSSLSuccess = 0,

    kSSLHandShakeInProgress = 1,
    kSSLHandShakeDone = 2,

    kSSLFail = -1,
    kSSLTimeout = -2,
    kSSLServerCertificateFail = -3,
    kSSLEncryptHashFail = -4,
    kSSLKickHandShakeFail = -5,
    kSSLWriteDecryptBIOFail = -6,
    kSSLReadDecryptSSLFail = -7,
    kSSLReadEncryptBIOFail = -9,
    kSSLWriteEncryptSSLFail = -10,
    kSSLCTXNewFail = -11,
    kSSLBIONewFail = -12,
    kSSLNewFail = -13,
    kSSLCTXVerifyLocationsFail = -14,
    kSSLCTXSetCipherFail = -15,
    kSSLWaitFail = -16
};

}

#endif // _SSL_STATUS_HPP__

#define LOG_CLASS "DTLS_mbedtls"
#include "../Include_i.h"

mbedtls_ssl_srtp_profile DTLS_SRTP_SUPPORTED_PROFILES[] = {
    MBEDTLS_SRTP_AES128_CM_HMAC_SHA1_80,
    MBEDTLS_SRTP_AES128_CM_HMAC_SHA1_32,
};

STATUS createDtlsSession(PDtlsSessionCallbacks pDtlsSessionCallbacks, TIMER_QUEUE_HANDLE timerQueueHandle,
        INT32 certificateBits, BOOL generateRSACertificate, PRtcCertificate pRtcCertificates, PDtlsSession* ppDtlsSession)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PDtlsSession pDtlsSession = NULL;
    PDtlsSessionCertificateInfo pCertInfo;
    UINT32 i, certCount;

    CHK(ppDtlsSession != NULL && pDtlsSessionCallbacks != NULL, STATUS_NULL_ARG);
    CHK_STATUS(dtlsValidateRtcCertificates(pRtcCertificates, &certCount));

    pDtlsSession = MEMCALLOC(SIZEOF(DtlsSession), 1);
    CHK(pDtlsSession != NULL, STATUS_NOT_ENOUGH_MEMORY);
    
    // initialize mbedtls stuff with sane values
    mbedtls_entropy_init(&pDtlsSession->entropy);
    mbedtls_ctr_drbg_init(&pDtlsSession->ctrDrbg);
    mbedtls_ssl_config_init(&pDtlsSession->sslCtxConfig);
    mbedtls_ssl_init(&pDtlsSession->sslCtx);
    CHK(mbedtls_ctr_drbg_seed(&pDtlsSession->ctrDrbg, mbedtls_entropy_func, &pDtlsSession->entropy, NULL, 0) == 0, STATUS_CREATE_SSL_FAILED);

    CHK_STATUS(createIOBuffer(MAX_UDP_PACKET_SIZE, &pDtlsSession->pReadBuffer));
    pDtlsSession->timerQueueHandle = timerQueueHandle;
    pDtlsSession->timerId = UINT32_MAX;
    pDtlsSession->sslLock = MUTEX_CREATE(TRUE);
    pDtlsSession->dtlsSessionCallbacks = *pDtlsSessionCallbacks;
    if (certificateBits == 0) {
        certificateBits = GENERATED_CERTIFICATE_BITS;
    }

    if (certCount == 0) {
        CHK_STATUS(createCertificateAndKey(certificateBits, generateRSACertificate, &pDtlsSession->ctrDrbg, &pDtlsSession->certificates[0]));
        pDtlsSession->certificates[0].created = TRUE;
        pDtlsSession->certificateCount = 1;
    } else {
        pDtlsSession->certificateCount = certCount;
        for (i = 0; i < certCount; i++) {
            pDtlsSession->certificates[i].cert = *(mbedtls_x509_crt*) pRtcCertificates[i].pCertificate;
            pDtlsSession->certificates[i].created = FALSE;
        }
    }

    // Generate and store the certificate fingerprints
    for (i = 0; i < pDtlsSession->certificateCount; i++) {
        pCertInfo = pDtlsSession->certificates + i;
        CHK_STATUS(dtlsCertificateFingerprint(&pCertInfo->cert, pCertInfo->fingerprint));
    }
    *ppDtlsSession = pDtlsSession;

CleanUp:

    CHK_LOG_ERR(retStatus);

    if (STATUS_FAILED(retStatus) && pDtlsSession != NULL) {
        freeDtlsSession(&pDtlsSession);
    }

    LEAVES();
    return retStatus;
}

STATUS freeDtlsSession(PDtlsSession *ppDtlsSession)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 i;
    PDtlsSessionCertificateInfo pCertInfo;
    PDtlsSession pDtlsSession;

    CHK(ppDtlsSession != NULL, STATUS_NULL_ARG);

    pDtlsSession = *ppDtlsSession;
    CHK(pDtlsSession != NULL, retStatus);

    if (pDtlsSession->timerId != UINT32_MAX) {
        timerQueueCancelTimer(pDtlsSession->timerQueueHandle, pDtlsSession->timerId, (UINT64) pDtlsSession);
    }

    for (i = 0; i < pDtlsSession->certificateCount; i++) {
        pCertInfo = pDtlsSession->certificates + i;
        if (pCertInfo->created) {
            mbedtls_x509_crt_free(&pCertInfo->cert);
            mbedtls_pk_free(&pCertInfo->privateKey);
        }
    }
    mbedtls_entropy_free(&pDtlsSession->entropy);
    mbedtls_ctr_drbg_free(&pDtlsSession->ctrDrbg);
    mbedtls_ssl_config_free(&pDtlsSession->sslCtxConfig);
    mbedtls_ssl_free(&pDtlsSession->sslCtx);

    freeIOBuffer(&pDtlsSession->pReadBuffer);
    if (IS_VALID_MUTEX_VALUE(pDtlsSession->sslLock)) {
        MUTEX_FREE(pDtlsSession->sslLock);
    }
    SAFE_MEMFREE(*ppDtlsSession);

CleanUp:
    LEAVES();
    return retStatus;
}

INT32 dtlsSessionSendCallback(PVOID customData, const unsigned char *pBuf, ULONG len)
{
  STATUS retStatus = STATUS_SUCCESS;
  PDtlsSession pDtlsSession = (PDtlsSession) customData;

  CHK(pDtlsSession != NULL, STATUS_NULL_ARG);

  pDtlsSession->dtlsSessionCallbacks.outboundPacketFn(pDtlsSession->dtlsSessionCallbacks.outBoundPacketFnCustomData, (PBYTE) pBuf, len);

CleanUp:

  return STATUS_FAILED(retStatus) ? -retStatus : len;
}

INT32 dtlsSessionReceiveCallback(PVOID customData, unsigned char *pBuf, ULONG len)
{
  STATUS retStatus = STATUS_SUCCESS;
  PDtlsSession pDtlsSession = (PDtlsSession) customData;
  PIOBuffer pBuffer;
  UINT32 readBytes = MBEDTLS_ERR_SSL_WANT_READ;

  CHK(pDtlsSession != NULL, STATUS_NULL_ARG);

  pBuffer = pDtlsSession->pReadBuffer;

  if (pBuffer->off < pBuffer->len) {
      CHK_STATUS(ioBufferRead(pBuffer, pBuf, len, &readBytes));
  }

CleanUp:

  return STATUS_FAILED(retStatus) ? -retStatus : readBytes;
}

// Provide mbedtls timer functionality for retransmission and timeout calculation
// Reference: https://tls.mbed.org/kb/how-to/dtls-tutorial
VOID dtlsSessionSetTimerCallback(PVOID customData, UINT32 intermediateDelayInMs, UINT32 finalDelayInMs)
{
    PDtlsSessionTimer pTimer = (PDtlsSessionTimer) customData;

    pTimer->intermediateDelay = intermediateDelayInMs * HUNDREDS_OF_NANOS_IN_A_MILLISECOND;
    pTimer->finalDelay = finalDelayInMs * HUNDREDS_OF_NANOS_IN_A_MILLISECOND;

    if (finalDelayInMs != 0) {
        pTimer->updatedTime = GETTIME();
    }
}

// Provide mbedtls timer functionality for retransmission and timeout calculation
// Reference: https://tls.mbed.org/kb/how-to/dtls-tutorial
//
// Returns:
//   -1: cancelled, set timer callback has been called with finalDelayInMs = 0;
//   0: no delays have passed
//   1: intermediate delay has passed
//   2: final delay has passed
INT32 dtlsSessionGetTimerCallback(PVOID customData)
{
    PDtlsSessionTimer pTimer = (PDtlsSessionTimer) customData;
    UINT64 elapsed = GETTIME() - pTimer->updatedTime;

    if (pTimer->finalDelay == 0) {
        return -1;
    } else if (elapsed >= pTimer->finalDelay) {
        return 2;
    } else if (elapsed >= pTimer->intermediateDelay) {
        return 1;
    } else {
        return 0;
    }
}

STATUS dtlsTransmissionTimerCallback(UINT32 timerID, UINT64 currentTime, UINT64 customData)
{
    UNUSED_PARAM(timerID);
    ENTERS();
    INT32 handshakeStatus;
    STATUS retStatus = STATUS_SUCCESS;
    PDtlsSession pDtlsSession = (PDtlsSession) customData;
    BOOL locked = FALSE;

    CHK(pDtlsSession != NULL, STATUS_NULL_ARG);

    MUTEX_LOCK(pDtlsSession->sslLock);
    locked = TRUE;

    handshakeStatus = mbedtls_ssl_handshake(&pDtlsSession->sslCtx);
    if (handshakeStatus == 0) {
        DLOGD("DTLS init completed. Time taken %" PRIu64 " ms",
              (currentTime - pDtlsSession->dtlsSessionStartTime) / HUNDREDS_OF_NANOS_IN_A_MILLISECOND);
        CHK_STATUS(dtlsSessionChangeState(pDtlsSession, CONNECTED));
        CHK(FALSE, STATUS_TIMER_QUEUE_STOP_SCHEDULING);
    } else if (handshakeStatus == MBEDTLS_ERR_SSL_WANT_READ || handshakeStatus == MBEDTLS_ERR_SSL_WANT_WRITE) {
        // No need to do anything when mbedtls needs more data. Another thread will provide the data.
        CHK(FALSE, STATUS_SUCCESS);
    } else {
        LOG_MBEDTLS_ERROR("mbedtls_ssl_handshake", handshakeStatus);
        CHK_STATUS(dtlsSessionChangeState(pDtlsSession, FAILED));
        CHK(FALSE, STATUS_TIMER_QUEUE_STOP_SCHEDULING);
    }

CleanUp:
    if (locked) {
        MUTEX_UNLOCK(pDtlsSession->sslLock);
    }

    LEAVES();
    return retStatus;
}

INT32 dtlsSessionKeyDerivationCallback(PVOID customData,
                                   const unsigned char *pMasterSecret,
                                   const unsigned char *pKeyBlock,
                                   ULONG maclen,
                                   ULONG keylen,
                                   ULONG ivlen,
                                   const unsigned char clientRandom[MAX_DTLS_RANDOM_BYTES_LEN],
                                   const unsigned char serverRandom[MAX_DTLS_RANDOM_BYTES_LEN],
                                   mbedtls_tls_prf_types tlsProfile)
{
    ENTER();
    UNUSED_PARAM(maclen);
    UNUSED_PARAM(keylen);
    UNUSED_PARAM(ivlen);
    PDtlsSession pDtlsSession = (PDtlsSession) customData;
    PTlsKeys pKeys = &pDtlsSession->tlsKeys;
    MEMCPY(pKeys->masterSecret, pMasterSecret, SIZEOF(pKeys->masterSecret));
    MEMCPY(pKeys->randBytes, clientRandom, MAX_DTLS_RANDOM_BYTES_LEN);
    MEMCPY(pKeys->randBytes + MAX_DTLS_RANDOM_BYTES_LEN, serverRandom, MAX_DTLS_RANDOM_BYTES_LEN);
    pKeys->tlsProfile = tlsProfile;
    LEAVE();
    return 0;
}

STATUS dtlsSessionStart(PDtlsSession pDtlsSession, BOOL isServer)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 i;
    BOOL locked = FALSE;
    PDtlsSessionCertificateInfo pCertInfo;

    CHK(pDtlsSession != NULL, STATUS_NULL_ARG);

    MUTEX_LOCK(pDtlsSession->sslLock);
    locked = TRUE;
    CHK(!ATOMIC_LOAD_BOOL(&pDtlsSession->isStarted), retStatus);

    // Need to set isStarted to TRUE after acquiring the lock to make sure dtlsSessionProcessPacket
    // dont proceed before dtlsSessionStart finish
    ATOMIC_STORE_BOOL(&pDtlsSession->isStarted, TRUE);
    CHK_STATUS(dtlsSessionChangeState(pDtlsSession, CONNECTING));

    // Initialize ssl config
    CHK(mbedtls_ssl_config_defaults(&pDtlsSession->sslCtxConfig,
                                isServer ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT,
                                MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                MBEDTLS_SSL_PRESET_DEFAULT) == 0, STATUS_CREATE_SSL_FAILED);
    // no need to verify since the certificate will be verified through SDP later
    mbedtls_ssl_conf_authmode(&pDtlsSession->sslCtxConfig, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_rng(&pDtlsSession->sslCtxConfig, mbedtls_ctr_drbg_random, &pDtlsSession->ctrDrbg);

    for (i = 0; i < pDtlsSession->certificateCount; i++) {
        pCertInfo = pDtlsSession->certificates + i;
        CHK(mbedtls_ssl_conf_own_cert(&pDtlsSession->sslCtxConfig, &pCertInfo->cert, &pCertInfo->privateKey) == 0, STATUS_CREATE_SSL_FAILED);
    }
    mbedtls_ssl_conf_dtls_cookies(&pDtlsSession->sslCtxConfig, NULL, NULL, NULL);
    CHK(mbedtls_ssl_conf_dtls_srtp_protection_profiles(&pDtlsSession->sslCtxConfig, 
                                                    DTLS_SRTP_SUPPORTED_PROFILES,
                                                    ARRAY_SIZE(DTLS_SRTP_SUPPORTED_PROFILES)) == 0, STATUS_CREATE_SSL_FAILED);
    mbedtls_ssl_conf_export_keys_ext_cb(&pDtlsSession->sslCtxConfig, dtlsSessionKeyDerivationCallback, pDtlsSession);

    CHK(mbedtls_ssl_setup(&pDtlsSession->sslCtx, &pDtlsSession->sslCtxConfig) == 0, STATUS_SSL_CTX_CREATION_FAILED);
    mbedtls_ssl_set_mtu(&pDtlsSession->sslCtx, MAX_UDP_PACKET_SIZE);
    mbedtls_ssl_set_bio(&pDtlsSession->sslCtx, pDtlsSession, dtlsSessionSendCallback, dtlsSessionReceiveCallback, NULL);
    mbedtls_ssl_set_timer_cb(&pDtlsSession->sslCtx, &pDtlsSession->transmissionTimer, dtlsSessionSetTimerCallback, dtlsSessionGetTimerCallback);

    // Start non-blocking handshaking
    pDtlsSession->dtlsSessionStartTime = GETTIME();
    CHK_STATUS(timerQueueAddTimer(pDtlsSession->timerQueueHandle, DTLS_SESSION_TIMER_START_DELAY,
                              DTLS_TRANSMISSION_INTERVAL, dtlsTransmissionTimerCallback, (UINT64) pDtlsSession,
                              &pDtlsSession->timerId));

CleanUp:
    if (locked) {
        MUTEX_UNLOCK(pDtlsSession->sslLock);
    }

    LEAVES();
    return retStatus;
}

STATUS dtlsSessionIsInitFinished(PDtlsSession pDtlsSession, PBOOL pIsFinished)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    CHK(pDtlsSession != NULL && pIsFinished != NULL, STATUS_NULL_ARG);
    MUTEX_LOCK(pDtlsSession->sslLock);
    *pIsFinished = pDtlsSession->state == CONNECTED;
    MUTEX_UNLOCK(pDtlsSession->sslLock);

CleanUp:
    LEAVES();
    return retStatus;
}

STATUS dtlsSessionProcessPacket(PDtlsSession pDtlsSession, PBYTE pData, PINT32 pDataLen)
{ 
    ENTER();
    STATUS retStatus = STATUS_SUCCESS;
    BOOL locked = FALSE;
    INT32 sslRet, readBytes = 0;
    PIOBuffer pReadBuffer;
    CHK(pDtlsSession != NULL && pData != NULL && pData != NULL, STATUS_NULL_ARG);
    CHK(ATOMIC_LOAD_BOOL(&pDtlsSession->isStarted), STATUS_SSL_PACKET_BEFORE_DTLS_READY);
    CHK(!ATOMIC_LOAD_BOOL(&pDtlsSession->shutdown), retStatus);

    MUTEX_LOCK(pDtlsSession->sslLock);
    locked = TRUE;

    pReadBuffer = pDtlsSession->pReadBuffer;
    CHK_STATUS(ioBufferWrite(pReadBuffer, pData, *pDataLen));

    // read application data
    while (pReadBuffer->off < pReadBuffer->len) {
        sslRet = mbedtls_ssl_read(&pDtlsSession->sslCtx, pData + readBytes, pReadBuffer->len - pReadBuffer->off);
        if (sslRet > 0) {
            readBytes += sslRet;
        } else if (sslRet == 0 || sslRet == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            // if sslRet is 0, the connection is closed already.
            // if sslRet is MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY, the client notified us that the connection is going to be closed.
            // In either case, we'll make sure that the state will change to CLOSED. If it's already closed, it'll be just a noop.
            DLOGD("Detected DTLS close_notify alert");
            CHK_STATUS(dtlsSessionShutdown(pDtlsSession));
            break;
        } else if (sslRet == MBEDTLS_ERR_SSL_WANT_READ || sslRet == MBEDTLS_ERR_SSL_WANT_WRITE) {
            break;
        } else {
            LOG_MBEDTLS_ERROR("mbedtls_ssl_read", sslRet);
            readBytes = 0;
            retStatus = STATUS_INTERNAL_ERROR;
            break;
        }
    }

CleanUp:
    if (pDataLen != NULL) {
        *pDataLen = readBytes;
    }

    if (locked) {
        MUTEX_UNLOCK(pDtlsSession->sslLock);
    }

    LEAVE();
    return retStatus;
}

STATUS dtlsSessionPutApplicationData(PDtlsSession pDtlsSession, PBYTE pData, INT32 dataLen)
{
    ENTER();
    STATUS retStatus = STATUS_SUCCESS;
    INT32 writtenBytes = 0;
    BOOL locked = FALSE;
    INT32 sslRet;

    CHK(pData != NULL, STATUS_NULL_ARG);
    CHK(!ATOMIC_LOAD_BOOL(&pDtlsSession->shutdown), retStatus);

    MUTEX_LOCK(pDtlsSession->sslLock);
    locked = TRUE;
    
    while (writtenBytes < dataLen) {
        sslRet = mbedtls_ssl_write(&pDtlsSession->sslCtx, pData + writtenBytes, dataLen - writtenBytes);
        if (sslRet > 0) {
            writtenBytes += sslRet;
        } else if (sslRet == MBEDTLS_ERR_SSL_WANT_READ || sslRet == MBEDTLS_ERR_SSL_WANT_WRITE) {
            break;
        } else {
            LOG_MBEDTLS_ERROR("mbedtls_ssl_write", sslRet);
            writtenBytes = 0;
            retStatus = STATUS_INTERNAL_ERROR;
            break;
        }
    }

CleanUp:
    if (locked) {
        MUTEX_UNLOCK(pDtlsSession->sslLock);
    }

    LEAVE();
    return STATUS_SUCCESS;
}

STATUS dtlsSessionGetLocalCertificateFingerprint(PDtlsSession pDtlsSession, PCHAR pBuff, UINT32 buffLen)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    BOOL locked = FALSE;

    CHK(pDtlsSession != NULL && pBuff != NULL, STATUS_NULL_ARG);
    CHK(buffLen >= CERTIFICATE_FINGERPRINT_LENGTH, STATUS_INVALID_ARG_LEN);

    MUTEX_LOCK(pDtlsSession->sslLock);
    locked = TRUE;

    // TODO: Use the 0th certificate for now
    MEMCPY(pBuff, pDtlsSession->certificates[0].fingerprint, buffLen);

CleanUp:
    if (locked) {
        MUTEX_UNLOCK(pDtlsSession->sslLock);
    }

    LEAVES();
    return retStatus;
}

STATUS dtlsSessionVerifyRemoteCertificateFingerprint(PDtlsSession pDtlsSession, PCHAR pExpectedFingerprint)
{ 
    ENTER();
    STATUS retStatus = STATUS_SUCCESS;
    CHAR actualFingerprint[CERTIFICATE_FINGERPRINT_LENGTH];
    mbedtls_x509_crt *pRemoteCertificate = NULL;
    BOOL locked = FALSE;

    CHK(pDtlsSession != NULL && pExpectedFingerprint != NULL, STATUS_NULL_ARG);

    MUTEX_LOCK(pDtlsSession->sslLock);
    locked = TRUE;

    CHK((pRemoteCertificate = (mbedtls_x509_crt*) mbedtls_ssl_get_peer_cert(&pDtlsSession->sslCtx)) != NULL, STATUS_INTERNAL_ERROR);
    CHK_STATUS(dtlsCertificateFingerprint(pRemoteCertificate, actualFingerprint));

    CHK(STRCMP(pExpectedFingerprint, actualFingerprint) == 0,  STATUS_SSL_REMOTE_CERTIFICATE_VERIFICATION_FAILED);

CleanUp:
    if (locked) {
        MUTEX_UNLOCK(pDtlsSession->sslLock);
    }

    LEAVE();
    return retStatus;
}

STATUS dtlsSessionPopulateKeyingMaterial(PDtlsSession pDtlsSession, PDtlsKeyingMaterial pDtlsKeyingMaterial)
{
    ENTER();
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 offset = 0;
    BOOL locked = FALSE;
    PTlsKeys pKeys;
    BYTE keyingMaterialBuffer[MAX_SRTP_MASTER_KEY_LEN * 2 + MAX_SRTP_SALT_KEY_LEN * 2];
    mbedtls_ssl_srtp_profile negotiatedSRTPProfile;

    CHK(pDtlsSession != NULL && pDtlsKeyingMaterial != NULL, STATUS_NULL_ARG);
    pKeys = &pDtlsSession->tlsKeys;

    MUTEX_LOCK(pDtlsSession->sslLock);
    locked = TRUE;

    CHK(mbedtls_ssl_tls_prf(pKeys->tlsProfile, 
                    pKeys->masterSecret,
                    ARRAY_SIZE(pKeys->masterSecret),
                    KEYING_EXTRACTOR_LABEL,
                    pKeys->randBytes,
                    ARRAY_SIZE(pKeys->randBytes),
                    keyingMaterialBuffer,
                    ARRAY_SIZE(keyingMaterialBuffer)) == 0, STATUS_INTERNAL_ERROR);
    
    pDtlsKeyingMaterial->key_length = MAX_SRTP_MASTER_KEY_LEN + MAX_SRTP_SALT_KEY_LEN;

    MEMCPY(pDtlsKeyingMaterial->clientWriteKey, &keyingMaterialBuffer[offset], MAX_SRTP_MASTER_KEY_LEN);
    offset += MAX_SRTP_MASTER_KEY_LEN;

    MEMCPY(pDtlsKeyingMaterial->serverWriteKey, &keyingMaterialBuffer[offset], MAX_SRTP_MASTER_KEY_LEN);
    offset += MAX_SRTP_MASTER_KEY_LEN;

    MEMCPY(pDtlsKeyingMaterial->clientWriteKey + MAX_SRTP_MASTER_KEY_LEN, &keyingMaterialBuffer[offset], MAX_SRTP_SALT_KEY_LEN);
    offset += MAX_SRTP_SALT_KEY_LEN;

    MEMCPY(pDtlsKeyingMaterial->serverWriteKey + MAX_SRTP_MASTER_KEY_LEN, &keyingMaterialBuffer[offset], MAX_SRTP_SALT_KEY_LEN);

    negotiatedSRTPProfile = mbedtls_ssl_get_dtls_srtp_protection_profile(&pDtlsSession->sslCtx);
    switch (negotiatedSRTPProfile) {
        case MBEDTLS_SRTP_AES128_CM_HMAC_SHA1_80:
            pDtlsKeyingMaterial->srtpProfile = SRTP_PROFILE_AES128_CM_HMAC_SHA1_80;
            break;
        case MBEDTLS_SRTP_AES128_CM_HMAC_SHA1_32:
            pDtlsKeyingMaterial->srtpProfile = SRTP_PROFILE_AES128_CM_HMAC_SHA1_32;
            break;
        default:
            CHK(FALSE, STATUS_SSL_UNKNOWN_SRTP_PROFILE);
    }

CleanUp:
    if (locked) {
        MUTEX_UNLOCK(pDtlsSession->sslLock);
    }

    LEAVE();
    return retStatus;
}

STATUS dtlsSessionShutdown(PDtlsSession pDtlsSession)
{
    STATUS retStatus = STATUS_SUCCESS;
    BOOL locked = FALSE;
    INT32 sslRet;

    CHK(pDtlsSession != NULL, STATUS_NULL_ARG);

    MUTEX_LOCK(pDtlsSession->sslLock);
    locked = TRUE;

    CHK(!ATOMIC_LOAD_BOOL(&pDtlsSession->shutdown), retStatus);

    do sslRet = mbedtls_ssl_close_notify(&pDtlsSession->sslCtx);
    while (sslRet == MBEDTLS_ERR_SSL_WANT_WRITE);

    ATOMIC_STORE_BOOL(&pDtlsSession->shutdown, TRUE);
    CHK_STATUS(dtlsSessionChangeState(pDtlsSession, CLOSED));

CleanUp:

    if (locked) {
        MUTEX_UNLOCK(pDtlsSession->sslLock);
    }

    return retStatus;
}

/**
 * createCertificateAndKey generates a new certificate and a key
 * If generateRSACertificate is true, RSA is going to be used for the key generation. Otherwise, ECDSA is going to be used.
 * certificateBits is only being used when generateRSACertificate is true.
 *
 * Expect:
 *  * pCtrDrbg to be initialized with a proper seed
 */
STATUS createCertificateAndKey(INT32 certificateBits, BOOL generateRSACertificate, mbedtls_ctr_drbg_context *pCtrDrbg, PDtlsSessionCertificateInfo pCertInfo)
{
    ENTER();
    STATUS retStatus = STATUS_SUCCESS;
    BOOL initialized = FALSE;
    CHAR certBuf[GENERATED_CERTIFICATE_MAX_SIZE];
    CHAR notBeforeBuf[MBEDTLS_X509_RFC5280_UTC_TIME_LEN + 1], notAfterBuf[MBEDTLS_X509_RFC5280_UTC_TIME_LEN + 1];
    UINT64 now, notAfter;
    UINT32 written;
    INT32 len;
    mbedtls_x509write_cert writeCert;
    mbedtls_mpi serial;

    CHK(!pCertInfo->created, STATUS_INVALID_ARG);
    CHK(pCertInfo != NULL, STATUS_INVALID_ARG);

    mbedtls_x509_crt *pCert = &pCertInfo->cert;
    mbedtls_pk_context *pKey = &pCertInfo->privateKey;

    // initialize to sane values
    mbedtls_mpi_init(&serial);
    mbedtls_x509write_crt_init(&writeCert);
    mbedtls_x509_crt_init(pCert); 
    mbedtls_pk_init(pKey);
    initialized = TRUE;

    // generate a key
    if (generateRSACertificate) {
        CHK(
            mbedtls_pk_setup(pKey, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) == 0 && \
            mbedtls_rsa_gen_key(mbedtls_pk_rsa(*pKey), mbedtls_ctr_drbg_random, pCtrDrbg, certificateBits, KVS_RSA_F4) == 0,
            STATUS_CERTIFICATE_GENERATION_FAILED);
    } else {
        CHK(
            mbedtls_pk_setup(pKey, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) == 0 && \
            mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(*pKey), mbedtls_ctr_drbg_random, pCtrDrbg) == 0,
            STATUS_CERTIFICATE_GENERATION_FAILED);
    }


    // generate a new certificate
    CHK(mbedtls_mpi_read_string(&serial, 10, STR(GENERATED_CERTIFICATE_SERIAL)) == 0, STATUS_CERTIFICATE_GENERATION_FAILED);

    now = GETTIME();
    CHK(generateTimestampStr(now, "%Y%m%d%H%M%S", notBeforeBuf, sizeof(notBeforeBuf), &written) == STATUS_SUCCESS, STATUS_CERTIFICATE_GENERATION_FAILED);
    notAfter = now + GENERATED_CERTIFICATE_DAYS * HUNDREDS_OF_NANOS_IN_A_DAY;
    CHK(generateTimestampStr(notAfter, "%Y%m%d%H%M%S", notAfterBuf, sizeof(notAfterBuf), &written) == STATUS_SUCCESS, STATUS_CERTIFICATE_GENERATION_FAILED);

    CHK(
        mbedtls_x509write_crt_set_serial(&writeCert, &serial) == 0 && \
        mbedtls_x509write_crt_set_validity(&writeCert, notBeforeBuf, notAfterBuf) == 0 && \
        mbedtls_x509write_crt_set_subject_name(&writeCert, "O=" GENERATED_CERTIFICATE_NAME ",CN=" GENERATED_CERTIFICATE_NAME) == 0 && \
        mbedtls_x509write_crt_set_issuer_name(&writeCert, "O=" GENERATED_CERTIFICATE_NAME ",CN=" GENERATED_CERTIFICATE_NAME) == 0,
        STATUS_CERTIFICATE_GENERATION_FAILED);
    // void functions, it must succeed
    mbedtls_x509write_crt_set_version(&writeCert, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_subject_key(&writeCert, pKey);
    mbedtls_x509write_crt_set_issuer_key(&writeCert, pKey);
    mbedtls_x509write_crt_set_md_alg(&writeCert, MBEDTLS_MD_SHA1);

    MEMSET(certBuf, 0, sizeof(certBuf));
    len = mbedtls_x509write_crt_der(&writeCert, (PVOID)certBuf, sizeof(certBuf), mbedtls_ctr_drbg_random, pCtrDrbg); 
    CHK(len >= 0, STATUS_CERTIFICATE_GENERATION_FAILED);

    // mbedtls_x509write_crt_der starts writing from behind, so we need to use the return len
    // to figure out where the data actually starts:
    //
    //         -----------------------------------------
    //         |  padding      |       certificate     |
    //         -----------------------------------------
    //         ^               ^
    //       certBuf   certBuf + (sizeof(certBuf) - len)
    CHK(mbedtls_x509_crt_parse_der(pCert, (PVOID)(certBuf + (sizeof(certBuf) - len)), len) == 0, STATUS_CERTIFICATE_GENERATION_FAILED);

CleanUp:
    if (initialized) {
        mbedtls_x509write_crt_free(&writeCert);
        mbedtls_mpi_free(&serial);

        if (STATUS_FAILED(retStatus)) {
            mbedtls_pk_free(pKey);
            mbedtls_x509_crt_free(pCert); 
        }
    }

    LEAVE();
    return retStatus;
}

STATUS dtlsCertificateFingerprint(mbedtls_x509_crt *pCert, PCHAR pBuff)
{
    ENTER();
    STATUS retStatus = STATUS_SUCCESS;
    BYTE fingerprint[MBEDTLS_MD_MAX_SIZE];
    INT32 sslRet, i, size;
    const mbedtls_md_info_t *pMdInfo;

    CHK(pBuff != NULL, STATUS_NULL_ARG);

    pMdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    CHK(pMdInfo != NULL, STATUS_INTERNAL_ERROR);

    sslRet = mbedtls_sha256_ret(pCert->raw.p, pCert->raw.len, fingerprint, 0);
    CHK(sslRet == 0, STATUS_INTERNAL_ERROR);

    size = mbedtls_md_get_size(pMdInfo);
    for (i = 0; i < size; i++) {
      SPRINTF(pBuff, "%.2X:", fingerprint[i]);
      pBuff += 3;
    }
    *(pBuff - 1) = '\0';

CleanUp:

    LEAVE();
    return retStatus;
}

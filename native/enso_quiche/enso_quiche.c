/*
 * JNI shim over cloudflare/libquiche for Enso's HTTP/3 layer.
 *
 * Netty's quic layer uses a JNI shim of this same shape.
 *
 * Conventions:
 *   - All pointers cross the boundary as jlong (raw address). Java side
 *     treats them opaquely.
 *   - Per-packet / per-stream-call byte[] arguments use
 *     GetPrimitiveArrayCritical: on HotSpot it returns the array's own
 *     storage (GetByteArrayElements always copies the whole array in, and
 *     back out unless JNI_ABORT). The critical-region rules hold because
 *     the region spans exactly one quiche call: quiche never calls back
 *     into the JVM (no qlog/keylog callbacks are installed) and doesn't
 *     block on anything a Java thread holds; no other JNI function is
 *     called while a region is open. Most calls return in microseconds,
 *     but quiche_conn_recv runs the TLS handshake inline: the packet
 *     carrying a ClientHello costs a CertificateVerify signature (around
 *     1 ms with an RSA-2048 key, far less with ECDSA) inside the region.
 *     On G1 (JDK 22+) a critical region pins just that array's heap
 *     region; collectors without region pinning stall GC for that long.
 *   - conn_send writes into a direct ByteBuffer (GetDirectBufferAddress),
 *     which DatagramChannel.send can then use without its own copy.
 *   - Cold-path calls (config, accept, retry, version negotiation) keep
 *     GetByteArrayElements: JNI_ABORT on release for read-only buffers,
 *     commit (0) for buffers we write into.
 *   - Sockaddrs are passed as (byte[] ip, int port). C builds the real
 *     struct sockaddr_in / _in6 on the JNI stack per call. Avoids
 *     shipping sockaddr_storage layout across the boundary (differs by
 *     OS) and keeps Java allocation-free.
 *   - Every function that can fail returns the raw quiche return code;
 *     Java handles QUICHE_ERR_DONE / < 0. Invalid arguments detected by
 *     the shim itself return SHIM_ERR_INVALID_ARGUMENT, outside quiche's
 *     error range.
 */

#include <jni.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>          /* struct timespec — quiche_send_info.at */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <quiche.h>

#define UNUSED(x) (void)(x)

/* Shim-detected bad arguments (bounds, address length). Distinct from
 * every quiche_error value; mirrored by Quiche.SHIM_ERR_INVALID_ARGUMENT. */
#define SHIM_ERR_INVALID_ARGUMENT (-10000)

/*
 * GetByteArrayElements returns NULL if the JVM can't pin/copy the array
 * (OOM, or a pending exception on env). Every call site must check —
 * a NULL pointer dereference inside quiche_* or memcpy crashes the JVM.
 * On NULL return, an exception is already pending on env; caller returns
 * an error sentinel and the pending exception surfaces on the Java side.
 */
#define GET_BYTES_OR_RETURN(dst, arr, ret)                                  \
    do {                                                                    \
        (dst) = (*env)->GetByteArrayElements(env, (arr), NULL);             \
        if ((dst) == NULL) { return (ret); }                                \
    } while (0)

/* Same but for functions that already hold one or more pinned arrays —
 * caller must release them before returning. */
#define GET_BYTES_OR_GOTO(dst, arr, label)                                  \
    do {                                                                    \
        (dst) = (*env)->GetByteArrayElements(env, (arr), NULL);             \
        if ((dst) == NULL) { goto label; }                                  \
    } while (0)

/*
 * Build a struct sockaddr from Java-side ip bytes + port. IPv4 → 4-byte
 * ipBytes, IPv6 → 16-byte ipBytes. Result is written into *out (must be
 * a sockaddr_storage-sized buffer). Returns socklen_t on success or 0
 * on invalid input.
 */
static socklen_t build_sockaddr(JNIEnv *env, jbyteArray ipArr, jint port,
                                struct sockaddr_storage *out) {
    if (ipArr == NULL) return 0;
    jsize ipLen = (*env)->GetArrayLength(env, ipArr);
    memset(out, 0, sizeof(*out));
    if (ipLen == 4) {
        struct sockaddr_in *sin = (struct sockaddr_in *)out;
        sin->sin_family = AF_INET;
        sin->sin_port = htons((uint16_t)port);
        (*env)->GetByteArrayRegion(env, ipArr, 0, 4, (jbyte *)&sin->sin_addr);
        return (socklen_t)sizeof(*sin);
    } else if (ipLen == 16) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)out;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons((uint16_t)port);
        (*env)->GetByteArrayRegion(env, ipArr, 0, 16, (jbyte *)&sin6->sin6_addr);
        return (socklen_t)sizeof(*sin6);
    }
    return 0;
}

/* --------------------------------------------------------------------- */
/* Version                                                                */
/* --------------------------------------------------------------------- */

JNIEXPORT jstring JNICALL
Java_com_s_1exp_enso_quiche_Quiche_version(JNIEnv *env, jclass cls) {
    UNUSED(cls);
    return (*env)->NewStringUTF(env, quiche_version());
}

/* --------------------------------------------------------------------- */
/* Config                                                                 */
/* --------------------------------------------------------------------- */

JNIEXPORT jlong JNICALL
Java_com_s_1exp_enso_quiche_Quiche_configNew(JNIEnv *env, jclass cls, jint version) {
    UNUSED(env); UNUSED(cls);
    return (jlong)(intptr_t)quiche_config_new((uint32_t)version);
}

JNIEXPORT void JNICALL
Java_com_s_1exp_enso_quiche_Quiche_configFree(JNIEnv *env, jclass cls, jlong config) {
    UNUSED(env); UNUSED(cls);
    quiche_config_free((quiche_config *)(intptr_t)config);
}

JNIEXPORT jint JNICALL
Java_com_s_1exp_enso_quiche_Quiche_configLoadCertChainFromPemFile(
        JNIEnv *env, jclass cls, jlong config, jstring path) {
    UNUSED(cls);
    const char *p = (*env)->GetStringUTFChars(env, path, NULL);
    int rc = quiche_config_load_cert_chain_from_pem_file(
        (quiche_config *)(intptr_t)config, p);
    (*env)->ReleaseStringUTFChars(env, path, p);
    return (jint)rc;
}

JNIEXPORT jint JNICALL
Java_com_s_1exp_enso_quiche_Quiche_configLoadPrivKeyFromPemFile(
        JNIEnv *env, jclass cls, jlong config, jstring path) {
    UNUSED(cls);
    const char *p = (*env)->GetStringUTFChars(env, path, NULL);
    int rc = quiche_config_load_priv_key_from_pem_file(
        (quiche_config *)(intptr_t)config, p);
    (*env)->ReleaseStringUTFChars(env, path, p);
    return (jint)rc;
}

JNIEXPORT jint JNICALL
Java_com_s_1exp_enso_quiche_Quiche_configSetApplicationProtos(
        JNIEnv *env, jclass cls, jlong config, jbyteArray protos) {
    UNUSED(cls);
    jsize len = (*env)->GetArrayLength(env, protos);
    jbyte *bytes;
    GET_BYTES_OR_RETURN(bytes, protos, -1);
    int rc = quiche_config_set_application_protos(
        (quiche_config *)(intptr_t)config, (const uint8_t *)bytes, (size_t)len);
    (*env)->ReleaseByteArrayElements(env, protos, bytes, JNI_ABORT);
    return (jint)rc;
}

#define CONFIG_SET_U64(name, cname)                                         \
JNIEXPORT void JNICALL                                                      \
Java_com_s_1exp_enso_quiche_Quiche_##name(JNIEnv *env, jclass cls,          \
                                          jlong config, jlong v) {          \
    UNUSED(env); UNUSED(cls);                                               \
    cname((quiche_config *)(intptr_t)config, (uint64_t)v);                  \
}

CONFIG_SET_U64(configSetMaxIdleTimeout, quiche_config_set_max_idle_timeout)
CONFIG_SET_U64(configSetMaxRecvUdpPayloadSize, quiche_config_set_max_recv_udp_payload_size)
CONFIG_SET_U64(configSetMaxSendUdpPayloadSize, quiche_config_set_max_send_udp_payload_size)
CONFIG_SET_U64(configSetInitialMaxData, quiche_config_set_initial_max_data)
CONFIG_SET_U64(configSetInitialMaxStreamDataBidiLocal, quiche_config_set_initial_max_stream_data_bidi_local)
CONFIG_SET_U64(configSetInitialMaxStreamDataBidiRemote, quiche_config_set_initial_max_stream_data_bidi_remote)
CONFIG_SET_U64(configSetInitialMaxStreamDataUni, quiche_config_set_initial_max_stream_data_uni)
CONFIG_SET_U64(configSetInitialMaxStreamsBidi, quiche_config_set_initial_max_streams_bidi)
CONFIG_SET_U64(configSetInitialMaxStreamsUni, quiche_config_set_initial_max_streams_uni)
CONFIG_SET_U64(configSetAckDelayExponent, quiche_config_set_ack_delay_exponent)
CONFIG_SET_U64(configSetMaxAckDelay, quiche_config_set_max_ack_delay)
CONFIG_SET_U64(configSetActiveConnectionIdLimit, quiche_config_set_active_connection_id_limit)

JNIEXPORT void JNICALL
Java_com_s_1exp_enso_quiche_Quiche_configSetDisableActiveMigration(
        JNIEnv *env, jclass cls, jlong config, jboolean v) {
    UNUSED(env); UNUSED(cls);
    quiche_config_set_disable_active_migration(
        (quiche_config *)(intptr_t)config, v == JNI_TRUE);
}

JNIEXPORT void JNICALL
Java_com_s_1exp_enso_quiche_Quiche_configVerifyPeer(
        JNIEnv *env, jclass cls, jlong config, jboolean v) {
    UNUSED(env); UNUSED(cls);
    quiche_config_verify_peer((quiche_config *)(intptr_t)config, v == JNI_TRUE);
}

/* --------------------------------------------------------------------- */
/* Accept / retry / negotiate / header_info                               */
/* --------------------------------------------------------------------- */

JNIEXPORT jlong JNICALL
Java_com_s_1exp_enso_quiche_Quiche_accept(
        JNIEnv *env, jclass cls,
        jbyteArray scidArr, jbyteArray odcidArr,
        jbyteArray localIp, jint localPort,
        jbyteArray peerIp, jint peerPort,
        jlong config) {
    UNUSED(cls);
    jsize scidLen = (*env)->GetArrayLength(env, scidArr);
    jbyte *scid;
    GET_BYTES_OR_RETURN(scid, scidArr, 0);
    /* odcidArr is null when no stateless retry occurred; quiche then
     * omits retry_source_connection_id from the server's transport
     * params (RFC 9000 §18.2). Passing a non-null odcid here without
     * having done a retry breaks the handshake — the client's
     * transport-param validation rejects with TRANSPORT_PARAMETER_ERROR
     * (code 0x8, reason "retry_source_connection_id does not match"). */
    jbyte *odcid = NULL;
    jsize odcidLen = 0;
    if (odcidArr != NULL) {
        odcidLen = (*env)->GetArrayLength(env, odcidArr);
        odcid = (*env)->GetByteArrayElements(env, odcidArr, NULL);
        if (odcid == NULL) {
            (*env)->ReleaseByteArrayElements(env, scidArr, scid, JNI_ABORT);
            return 0;
        }
    }

    struct sockaddr_storage local, peer;
    socklen_t localLen = build_sockaddr(env, localIp, localPort, &local);
    socklen_t peerLen = build_sockaddr(env, peerIp, peerPort, &peer);
    if (localLen == 0 || peerLen == 0) {
        (*env)->ReleaseByteArrayElements(env, scidArr, scid, JNI_ABORT);
        if (odcid != NULL) {
            (*env)->ReleaseByteArrayElements(env, odcidArr, odcid, JNI_ABORT);
        }
        return 0; /* Java treats 0 handle as null → accept failure. */
    }

    quiche_conn *conn = quiche_accept(
        (const uint8_t *)scid, (size_t)scidLen,
        (const uint8_t *)odcid, (size_t)odcidLen,
        (const struct sockaddr *)&local, localLen,
        (const struct sockaddr *)&peer, peerLen,
        (quiche_config *)(intptr_t)config);

    (*env)->ReleaseByteArrayElements(env, scidArr, scid, JNI_ABORT);
    if (odcid != NULL) {
        (*env)->ReleaseByteArrayElements(env, odcidArr, odcid, JNI_ABORT);
    }
    return (jlong)(intptr_t)conn;
}

/* Client-side connection. Used by the test suite to drive the server
 * over real QUIC with hand-built HTTP/3 frames. */
JNIEXPORT jlong JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connect(
        JNIEnv *env, jclass cls,
        jstring serverName, jbyteArray scidArr,
        jbyteArray localIp, jint localPort,
        jbyteArray peerIp, jint peerPort,
        jlong config) {
    UNUSED(cls);
    uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
    jsize scidLen = (*env)->GetArrayLength(env, scidArr);
    if (scidLen > QUICHE_MAX_CONN_ID_LEN) return 0;
    (*env)->GetByteArrayRegion(env, scidArr, 0, scidLen, (jbyte *)scid);
    struct sockaddr_storage local, peer;
    socklen_t localLen = build_sockaddr(env, localIp, localPort, &local);
    socklen_t peerLen = build_sockaddr(env, peerIp, peerPort, &peer);
    if (localLen == 0 || peerLen == 0) return 0;
    const char *name = (*env)->GetStringUTFChars(env, serverName, NULL);
    if (name == NULL) return 0;
    quiche_conn *conn = quiche_connect(
        name, scid, (size_t)scidLen,
        (const struct sockaddr *)&local, localLen,
        (const struct sockaddr *)&peer, peerLen,
        (quiche_config *)(intptr_t)config);
    (*env)->ReleaseStringUTFChars(env, serverName, name);
    return (jlong)(intptr_t)conn;
}

JNIEXPORT jlong JNICALL
Java_com_s_1exp_enso_quiche_Quiche_retry(
        JNIEnv *env, jclass cls,
        jbyteArray scidArr, jbyteArray dcidArr,
        jbyteArray newScidArr, jbyteArray tokenArr,
        jint version, jbyteArray outArr) {
    UNUSED(cls);
    jsize scidLen = (*env)->GetArrayLength(env, scidArr);
    jsize dcidLen = (*env)->GetArrayLength(env, dcidArr);
    jsize newLen = (*env)->GetArrayLength(env, newScidArr);
    jsize tokLen = (*env)->GetArrayLength(env, tokenArr);
    jsize outLen = (*env)->GetArrayLength(env, outArr);

    jbyte *scid = NULL, *dcid = NULL, *newScid = NULL, *tok = NULL, *out = NULL;
    ssize_t rc = -1; /* QUICHE_ERR_DONE surrogate for unwind */
    GET_BYTES_OR_GOTO(scid, scidArr, retry_unwind);
    GET_BYTES_OR_GOTO(dcid, dcidArr, retry_unwind);
    GET_BYTES_OR_GOTO(newScid, newScidArr, retry_unwind);
    GET_BYTES_OR_GOTO(tok, tokenArr, retry_unwind);
    GET_BYTES_OR_GOTO(out, outArr, retry_unwind);

    rc = quiche_retry(
        (const uint8_t *)scid, (size_t)scidLen,
        (const uint8_t *)dcid, (size_t)dcidLen,
        (const uint8_t *)newScid, (size_t)newLen,
        (const uint8_t *)tok, (size_t)tokLen,
        (uint32_t)version, (uint8_t *)out, (size_t)outLen);

retry_unwind:
    if (out != NULL) (*env)->ReleaseByteArrayElements(env, outArr, out, 0); /* commit */
    if (tok != NULL) (*env)->ReleaseByteArrayElements(env, tokenArr, tok, JNI_ABORT);
    if (newScid != NULL) (*env)->ReleaseByteArrayElements(env, newScidArr, newScid, JNI_ABORT);
    if (dcid != NULL) (*env)->ReleaseByteArrayElements(env, dcidArr, dcid, JNI_ABORT);
    if (scid != NULL) (*env)->ReleaseByteArrayElements(env, scidArr, scid, JNI_ABORT);
    return (jlong)rc;
}

JNIEXPORT jlong JNICALL
Java_com_s_1exp_enso_quiche_Quiche_negotiateVersion(
        JNIEnv *env, jclass cls,
        jbyteArray scidArr, jbyteArray dcidArr, jbyteArray outArr) {
    UNUSED(cls);
    jsize scidLen = (*env)->GetArrayLength(env, scidArr);
    jsize dcidLen = (*env)->GetArrayLength(env, dcidArr);
    jsize outLen = (*env)->GetArrayLength(env, outArr);

    jbyte *scid = NULL, *dcid = NULL, *out = NULL;
    ssize_t rc = -1;
    GET_BYTES_OR_GOTO(scid, scidArr, negotiate_unwind);
    GET_BYTES_OR_GOTO(dcid, dcidArr, negotiate_unwind);
    GET_BYTES_OR_GOTO(out, outArr, negotiate_unwind);

    rc = quiche_negotiate_version(
        (const uint8_t *)scid, (size_t)scidLen,
        (const uint8_t *)dcid, (size_t)dcidLen,
        (uint8_t *)out, (size_t)outLen);

negotiate_unwind:
    if (out != NULL) (*env)->ReleaseByteArrayElements(env, outArr, out, 0);
    if (dcid != NULL) (*env)->ReleaseByteArrayElements(env, dcidArr, dcid, JNI_ABORT);
    if (scid != NULL) (*env)->ReleaseByteArrayElements(env, scidArr, scid, JNI_ABORT);
    return (jlong)rc;
}

/*
 * Parses the header of the datagram in the direct buffer bufObj[0, bufLen).
 * Java passes the *max* sizes in scidLen[0]/dcidLen[0]/tokenLen[0]; on
 * success they receive the actual lengths and only those bytes are copied
 * into scid/dcid/token.
 */
JNIEXPORT jint JNICALL
Java_com_s_1exp_enso_quiche_Quiche_headerInfo(
        JNIEnv *env, jclass cls,
        jobject bufObj, jint bufLen, jint dcil,
        jintArray versionOut, jbyteArray typeOut,
        jbyteArray scidArr, jlongArray scidLenArr,
        jbyteArray dcidArr, jlongArray dcidLenArr,
        jbyteArray tokenArr, jlongArray tokenLenArr) {
    UNUSED(cls);
    uint8_t *buf = (uint8_t *)(*env)->GetDirectBufferAddress(env, bufObj);
    jlong cap = (*env)->GetDirectBufferCapacity(env, bufObj);
    if (buf == NULL || bufLen < 0 || bufLen > cap) return SHIM_ERR_INVALID_ARGUMENT;

    jlong scidLenJ, dcidLenJ, tokenLenJ;
    (*env)->GetLongArrayRegion(env, scidLenArr, 0, 1, &scidLenJ);
    (*env)->GetLongArrayRegion(env, dcidLenArr, 0, 1, &dcidLenJ);
    (*env)->GetLongArrayRegion(env, tokenLenArr, 0, 1, &tokenLenJ);
    /* Caller-supplied max sizes must fit both the Java arrays and our
     * stack buffers. */
    if (scidLenJ < 0 || scidLenJ > QUICHE_MAX_CONN_ID_LEN
        || scidLenJ > (*env)->GetArrayLength(env, scidArr)
        || dcidLenJ < 0 || dcidLenJ > QUICHE_MAX_CONN_ID_LEN
        || dcidLenJ > (*env)->GetArrayLength(env, dcidArr)
        || tokenLenJ < 0 || tokenLenJ > 4096
        || tokenLenJ > (*env)->GetArrayLength(env, tokenArr)) {
        return SHIM_ERR_INVALID_ARGUMENT;
    }

    uint8_t scid[QUICHE_MAX_CONN_ID_LEN], dcid[QUICHE_MAX_CONN_ID_LEN], token[4096];
    size_t scidLen = (size_t)scidLenJ;
    size_t dcidLen = (size_t)dcidLenJ;
    size_t tokenLen = (size_t)tokenLenJ;
    uint32_t version;
    uint8_t type;

    int rc = quiche_header_info(
        buf, (size_t)bufLen, (size_t)dcil,
        &version, &type,
        scid, &scidLen,
        dcid, &dcidLen,
        token, &tokenLen);
    if (rc != 0) return (jint)rc;

    jint vJ = (jint)version;
    (*env)->SetIntArrayRegion(env, versionOut, 0, 1, &vJ);
    jbyte tJ = (jbyte)type;
    (*env)->SetByteArrayRegion(env, typeOut, 0, 1, &tJ);
    (*env)->SetByteArrayRegion(env, scidArr, 0, (jsize)scidLen, (jbyte *)scid);
    (*env)->SetByteArrayRegion(env, dcidArr, 0, (jsize)dcidLen, (jbyte *)dcid);
    (*env)->SetByteArrayRegion(env, tokenArr, 0, (jsize)tokenLen, (jbyte *)token);
    jlong sJ = (jlong)scidLen, dJ = (jlong)dcidLen, tJl = (jlong)tokenLen;
    (*env)->SetLongArrayRegion(env, scidLenArr, 0, 1, &sJ);
    (*env)->SetLongArrayRegion(env, dcidLenArr, 0, 1, &dJ);
    (*env)->SetLongArrayRegion(env, tokenLenArr, 0, 1, &tJl);
    return 0;
}

JNIEXPORT jboolean JNICALL
Java_com_s_1exp_enso_quiche_Quiche_versionIsSupported(
        JNIEnv *env, jclass cls, jint version) {
    UNUSED(env); UNUSED(cls);
    return quiche_version_is_supported((uint32_t)version) ? JNI_TRUE : JNI_FALSE;
}

/* --------------------------------------------------------------------- */
/* Conn lifecycle + state                                                 */
/* --------------------------------------------------------------------- */

JNIEXPORT void JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connFree(JNIEnv *env, jclass cls, jlong conn) {
    UNUSED(env); UNUSED(cls);
    quiche_conn_free((quiche_conn *)(intptr_t)conn);
}

JNIEXPORT jboolean JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connIsClosed(JNIEnv *env, jclass cls, jlong conn) {
    UNUSED(env); UNUSED(cls);
    return quiche_conn_is_closed((quiche_conn *)(intptr_t)conn) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connIsEstablished(JNIEnv *env, jclass cls, jlong conn) {
    UNUSED(env); UNUSED(cls);
    return quiche_conn_is_established((quiche_conn *)(intptr_t)conn) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jlong JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connTimeoutAsNanos(JNIEnv *env, jclass cls, jlong conn) {
    UNUSED(env); UNUSED(cls);
    uint64_t v = quiche_conn_timeout_as_nanos((quiche_conn *)(intptr_t)conn);
    /* quiche uses UINT64_MAX as "no timeout"; Java expects -1. */
    if (v == UINT64_MAX) return -1L;
    return (jlong)v;
}

JNIEXPORT void JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connOnTimeout(JNIEnv *env, jclass cls, jlong conn) {
    UNUSED(env); UNUSED(cls);
    quiche_conn_on_timeout((quiche_conn *)(intptr_t)conn);
}

/* Fills out[0] = 1 when the peer's CONNECTION_CLOSE was application
 * level (0 for transport), out[1] = its error code. Returns false when
 * the peer has not closed the connection. */
JNIEXPORT jboolean JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connPeerError(
        JNIEnv *env, jclass cls, jlong conn, jlongArray out) {
    UNUSED(cls);
    bool isApp = false;
    uint64_t code = 0;
    const uint8_t *reason = NULL;
    size_t reasonLen = 0;
    if (!quiche_conn_peer_error((quiche_conn *)(intptr_t)conn,
                                &isApp, &code, &reason, &reasonLen)) {
        return JNI_FALSE;
    }
    jlong vals[2] = { isApp ? 1 : 0, (jlong)code };
    (*env)->SetLongArrayRegion(env, out, 0, 2, vals);
    return JNI_TRUE;
}

JNIEXPORT jlong JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connRecv(
        JNIEnv *env, jclass cls, jlong conn,
        jbyteArray bufArr, jint bufLen,
        jbyteArray fromIp, jint fromPort,
        jbyteArray toIp, jint toPort) {
    UNUSED(cls);
    struct sockaddr_storage from, to;
    socklen_t fromLen = build_sockaddr(env, fromIp, fromPort, &from);
    socklen_t toLen = build_sockaddr(env, toIp, toPort, &to);
    if (fromLen == 0 || toLen == 0) return SHIM_ERR_INVALID_ARGUMENT;
    /* Bounds-check caller-supplied length against actual array length.
     * A bug in the Java layer that passes bufLen > array.length would
     * make libquiche read past the array → OOB / crash. */
    jsize arrLen = (*env)->GetArrayLength(env, bufArr);
    if (bufLen < 0 || bufLen > arrLen) return SHIM_ERR_INVALID_ARGUMENT;
    quiche_recv_info info = {
        .from = (struct sockaddr *)&from, .from_len = fromLen,
        .to = (struct sockaddr *)&to, .to_len = toLen,
    };
    /* quiche decrypts in place; the datagram array is the owner thread's
     * own copy and discarded afterwards, so no copy-back is needed. */
    uint8_t *buf = (*env)->GetPrimitiveArrayCritical(env, bufArr, NULL);
    if (buf == NULL) return SHIM_ERR_INVALID_ARGUMENT;
    ssize_t rc = quiche_conn_recv(
        (quiche_conn *)(intptr_t)conn, buf, (size_t)bufLen, &info);
    (*env)->ReleasePrimitiveArrayCritical(env, bufArr, buf, JNI_ABORT);
    return (jlong)rc;
}

/*
 * Writes one packet into the direct buffer outObj[0, outLen). On success
 * the destination quiche chose (send_info.to — differs from the original
 * peer after a NAT rebinding / migration) is written to toIpOut (4 or 16
 * bytes) and toMetaOut = {port, ip length}. send_info.at (pacing) is not
 * used.
 */
JNIEXPORT jlong JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connSend(
        JNIEnv *env, jclass cls, jlong conn,
        jobject outObj, jint outLen,
        jbyteArray toIpOut, jintArray toMetaOut) {
    UNUSED(cls);
    uint8_t *out = (uint8_t *)(*env)->GetDirectBufferAddress(env, outObj);
    jlong cap = (*env)->GetDirectBufferCapacity(env, outObj);
    if (out == NULL || outLen < 0 || outLen > cap) return SHIM_ERR_INVALID_ARGUMENT;
    quiche_send_info info;
    memset(&info, 0, sizeof(info));
    ssize_t rc = quiche_conn_send(
        (quiche_conn *)(intptr_t)conn, out, (size_t)outLen, &info);
    if (rc < 0) return (jlong)rc;
    jint meta[2] = { 0, 0 };
    if (info.to.ss_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&info.to;
        meta[0] = ntohs(sin->sin_port);
        meta[1] = 4;
        (*env)->SetByteArrayRegion(env, toIpOut, 0, 4, (jbyte *)&sin->sin_addr);
    } else if (info.to.ss_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&info.to;
        meta[0] = ntohs(sin6->sin6_port);
        meta[1] = 16;
        (*env)->SetByteArrayRegion(env, toIpOut, 0, 16, (jbyte *)&sin6->sin6_addr);
    }
    (*env)->SetIntArrayRegion(env, toMetaOut, 0, 2, meta);
    return (jlong)rc;
}

JNIEXPORT jint JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connClose(
        JNIEnv *env, jclass cls, jlong conn,
        jboolean app, jlong err, jbyteArray reasonArr) {
    UNUSED(cls);
    jsize len = (reasonArr != NULL) ? (*env)->GetArrayLength(env, reasonArr) : 0;
    jbyte *reason = NULL;
    if (len > 0) {
        reason = (*env)->GetByteArrayElements(env, reasonArr, NULL);
        if (reason == NULL) return -1;
    }
    int rc = quiche_conn_close(
        (quiche_conn *)(intptr_t)conn,
        app == JNI_TRUE, (uint64_t)err,
        (const uint8_t *)reason, (size_t)len);
    if (reason != NULL) {
        (*env)->ReleaseByteArrayElements(env, reasonArr, reason, JNI_ABORT);
    }
    return (jint)rc;
}

/* --------------------------------------------------------------------- */
/* Streams                                                                */
/* --------------------------------------------------------------------- */

JNIEXPORT jlong JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connStreamCapacity(
        JNIEnv *env, jclass cls, jlong conn, jlong streamId) {
    UNUSED(env); UNUSED(cls);
    return (jlong)quiche_conn_stream_capacity(
        (quiche_conn *)(intptr_t)conn, (uint64_t)streamId);
}

JNIEXPORT jlong JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connStreamRecv(
        JNIEnv *env, jclass cls, jlong conn, jlong streamId,
        jbyteArray outArr, jint outLen,
        jbooleanArray finOut, jlongArray errOut) {
    UNUSED(cls);
    jsize arrLen = (*env)->GetArrayLength(env, outArr);
    if (outLen < 0 || outLen > arrLen) return SHIM_ERR_INVALID_ARGUMENT;
    bool fin = false;
    uint64_t err = 0;
    uint8_t *out = (*env)->GetPrimitiveArrayCritical(env, outArr, NULL);
    if (out == NULL) return SHIM_ERR_INVALID_ARGUMENT;
    ssize_t rc = quiche_conn_stream_recv(
        (quiche_conn *)(intptr_t)conn, (uint64_t)streamId,
        out, (size_t)outLen, &fin, &err);
    (*env)->ReleasePrimitiveArrayCritical(env, outArr, out, 0);
    jboolean finJ = fin ? JNI_TRUE : JNI_FALSE;
    (*env)->SetBooleanArrayRegion(env, finOut, 0, 1, &finJ);
    if (errOut != NULL) {
        jlong errJ = (jlong)err;
        (*env)->SetLongArrayRegion(env, errOut, 0, 1, &errJ);
    }
    return (jlong)rc;
}

JNIEXPORT jlong JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connStreamSend(
        JNIEnv *env, jclass cls, jlong conn, jlong streamId,
        jbyteArray bufArr, jint off, jint len, jboolean fin) {
    UNUSED(cls);
    jsize arrLen = (*env)->GetArrayLength(env, bufArr);
    if (off < 0 || len < 0 || (jlong)off + (jlong)len > (jlong)arrLen) {
        return SHIM_ERR_INVALID_ARGUMENT;
    }
    /* out_error_code (the peer's STOP_SENDING code) is not needed: the
     * caller only distinguishes STREAM_STOPPED / STREAM_RESET. */
    uint64_t err = 0;
    uint8_t *buf = (*env)->GetPrimitiveArrayCritical(env, bufArr, NULL);
    if (buf == NULL) return SHIM_ERR_INVALID_ARGUMENT;
    ssize_t rc = quiche_conn_stream_send(
        (quiche_conn *)(intptr_t)conn, (uint64_t)streamId,
        buf + off, (size_t)len, fin == JNI_TRUE, &err);
    (*env)->ReleasePrimitiveArrayCritical(env, bufArr, buf, JNI_ABORT);
    return (jlong)rc;
}

JNIEXPORT jint JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connStreamShutdown(
        JNIEnv *env, jclass cls, jlong conn, jlong streamId,
        jint direction, jlong err) {
    UNUSED(env); UNUSED(cls);
    return (jint)quiche_conn_stream_shutdown(
        (quiche_conn *)(intptr_t)conn, (uint64_t)streamId,
        (enum quiche_shutdown)direction, (uint64_t)err);
}

JNIEXPORT jlong JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connReadable(JNIEnv *env, jclass cls, jlong conn) {
    UNUSED(env); UNUSED(cls);
    return (jlong)(intptr_t)quiche_conn_readable(
        (quiche_conn *)(intptr_t)conn);
}

JNIEXPORT jboolean JNICALL
Java_com_s_1exp_enso_quiche_Quiche_streamIterNext(
        JNIEnv *env, jclass cls, jlong iter, jlongArray streamIdOut) {
    UNUSED(cls);
    uint64_t sid = 0;
    bool has = quiche_stream_iter_next(
        (quiche_stream_iter *)(intptr_t)iter, &sid);
    if (has) {
        jlong sJ = (jlong)sid;
        (*env)->SetLongArrayRegion(env, streamIdOut, 0, 1, &sJ);
    }
    return has ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL
Java_com_s_1exp_enso_quiche_Quiche_streamIterFree(JNIEnv *env, jclass cls, jlong iter) {
    UNUSED(env); UNUSED(cls);
    quiche_stream_iter_free((quiche_stream_iter *)(intptr_t)iter);
}

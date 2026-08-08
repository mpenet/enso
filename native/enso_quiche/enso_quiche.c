/*
 * JNI shim over cloudflare/libquiche for Enso's HTTP/3 layer.
 *
 * We use JNI (not FFM) because the FFM downcall path on JDK 25 + macOS
 * ARM64 corrupts libmalloc's freelist under connection churn (task
 * #86/#79; also see JDK-8357145 / JDK-8357268 that Netty steers around
 * in CleanerJava25.java). Netty's own quic layer uses a JNI shim of
 * this exact shape.
 *
 * Conventions:
 *   - All pointers cross the boundary as jlong (raw address). Java side
 *     treats them opaquely.
 *   - Byte arrays use GetByteArrayElements. HotSpot avoids the copy when
 *     the JVM can pin the underlying heap array. GetPrimitiveArrayCritical
 *     is NOT viable here because every downcall wraps a real quiche
 *     function call, which may itself invoke stdlib routines — the
 *     critical section rule (no JNI, no blocking, no lock-taking) is
 *     hard to guarantee across those.
 *   - Buffers we only read → JNI_ABORT on release (skip copy-back).
 *     Buffers we write into for the caller → commit (0).
 *   - Sockaddrs are passed as (byte[] ip, int port). C builds the real
 *     struct sockaddr_in / _in6 on the JNI stack per call. Avoids
 *     shipping sockaddr_storage layout across the boundary (differs by
 *     OS) and keeps Java allocation-free.
 *   - Every function that can fail returns the raw quiche return code;
 *     Java handles QUICHE_ERR_DONE / < 0.
 */

#include <jni.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <quiche.h>

#define UNUSED(x) (void)(x)

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
    jbyte *bytes = (*env)->GetByteArrayElements(env, protos, NULL);
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

JNIEXPORT void JNICALL
Java_com_s_1exp_enso_quiche_Quiche_configSetDisableActiveMigration(
        JNIEnv *env, jclass cls, jlong config, jboolean v) {
    UNUSED(env); UNUSED(cls);
    quiche_config_set_disable_active_migration(
        (quiche_config *)(intptr_t)config, v == JNI_TRUE);
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
    jsize odcidLen = (*env)->GetArrayLength(env, odcidArr);
    jbyte *scid = (*env)->GetByteArrayElements(env, scidArr, NULL);
    jbyte *odcid = (*env)->GetByteArrayElements(env, odcidArr, NULL);

    struct sockaddr_storage local, peer;
    socklen_t localLen = build_sockaddr(env, localIp, localPort, &local);
    socklen_t peerLen = build_sockaddr(env, peerIp, peerPort, &peer);
    if (localLen == 0 || peerLen == 0) {
        (*env)->ReleaseByteArrayElements(env, scidArr, scid, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, odcidArr, odcid, JNI_ABORT);
        return 0; /* Java treats 0 handle as null → accept failure. */
    }

    quiche_conn *conn = quiche_accept(
        (const uint8_t *)scid, (size_t)scidLen,
        (const uint8_t *)odcid, (size_t)odcidLen,
        (const struct sockaddr *)&local, localLen,
        (const struct sockaddr *)&peer, peerLen,
        (quiche_config *)(intptr_t)config);

    (*env)->ReleaseByteArrayElements(env, scidArr, scid, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, odcidArr, odcid, JNI_ABORT);
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

    jbyte *scid = (*env)->GetByteArrayElements(env, scidArr, NULL);
    jbyte *dcid = (*env)->GetByteArrayElements(env, dcidArr, NULL);
    jbyte *newScid = (*env)->GetByteArrayElements(env, newScidArr, NULL);
    jbyte *tok = (*env)->GetByteArrayElements(env, tokenArr, NULL);
    jbyte *out = (*env)->GetByteArrayElements(env, outArr, NULL);

    ssize_t rc = quiche_retry(
        (const uint8_t *)scid, (size_t)scidLen,
        (const uint8_t *)dcid, (size_t)dcidLen,
        (const uint8_t *)newScid, (size_t)newLen,
        (const uint8_t *)tok, (size_t)tokLen,
        (uint32_t)version, (uint8_t *)out, (size_t)outLen);

    (*env)->ReleaseByteArrayElements(env, scidArr, scid, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, dcidArr, dcid, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, newScidArr, newScid, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, tokenArr, tok, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, outArr, out, 0); /* commit */
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

    jbyte *scid = (*env)->GetByteArrayElements(env, scidArr, NULL);
    jbyte *dcid = (*env)->GetByteArrayElements(env, dcidArr, NULL);
    jbyte *out = (*env)->GetByteArrayElements(env, outArr, NULL);

    ssize_t rc = quiche_negotiate_version(
        (const uint8_t *)scid, (size_t)scidLen,
        (const uint8_t *)dcid, (size_t)dcidLen,
        (uint8_t *)out, (size_t)outLen);

    (*env)->ReleaseByteArrayElements(env, scidArr, scid, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, dcidArr, dcid, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, outArr, out, 0);
    return (jlong)rc;
}

/*
 * Header info out-params. Java pre-sizes scid/dcid/token to max length
 * and passes in the *max* size as scidLen[0]/dcidLen[0]/tokenLen[0].
 * quiche writes back the actual lengths.
 */
JNIEXPORT jint JNICALL
Java_com_s_1exp_enso_quiche_Quiche_headerInfo(
        JNIEnv *env, jclass cls,
        jbyteArray bufArr, jint bufLen, jint dcil,
        jintArray versionOut, jbyteArray typeOut,
        jbyteArray scidArr, jlongArray scidLenArr,
        jbyteArray dcidArr, jlongArray dcidLenArr,
        jbyteArray tokenArr, jlongArray tokenLenArr) {
    UNUSED(cls);
    jbyte *buf = (*env)->GetByteArrayElements(env, bufArr, NULL);
    jbyte *scid = (*env)->GetByteArrayElements(env, scidArr, NULL);
    jbyte *dcid = (*env)->GetByteArrayElements(env, dcidArr, NULL);
    jbyte *token = (*env)->GetByteArrayElements(env, tokenArr, NULL);

    jlong scidLenJ, dcidLenJ, tokenLenJ;
    (*env)->GetLongArrayRegion(env, scidLenArr, 0, 1, &scidLenJ);
    (*env)->GetLongArrayRegion(env, dcidLenArr, 0, 1, &dcidLenJ);
    (*env)->GetLongArrayRegion(env, tokenLenArr, 0, 1, &tokenLenJ);

    size_t scidLen = (size_t)scidLenJ;
    size_t dcidLen = (size_t)dcidLenJ;
    size_t tokenLen = (size_t)tokenLenJ;
    uint32_t version;
    uint8_t type;

    int rc = quiche_header_info(
        (const uint8_t *)buf, (size_t)bufLen, (size_t)dcil,
        &version, &type,
        (uint8_t *)scid, &scidLen,
        (uint8_t *)dcid, &dcidLen,
        (uint8_t *)token, &tokenLen);

    /* On error paths quiche may have partially clobbered scid/dcid/token —
     * caller ignores them anyway, so skip the copy-back to avoid a real
     * memcpy in the pinned-array fallback. */
    jint releaseMode = (rc == 0) ? 0 : JNI_ABORT;
    (*env)->ReleaseByteArrayElements(env, bufArr, buf, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, scidArr, scid, releaseMode);
    (*env)->ReleaseByteArrayElements(env, dcidArr, dcid, releaseMode);
    (*env)->ReleaseByteArrayElements(env, tokenArr, token, releaseMode);

    if (rc == 0) {
        jint vJ = (jint)version;
        (*env)->SetIntArrayRegion(env, versionOut, 0, 1, &vJ);
        jbyte tJ = (jbyte)type;
        (*env)->SetByteArrayRegion(env, typeOut, 0, 1, &tJ);
        jlong sJ = (jlong)scidLen, dJ = (jlong)dcidLen, tJl = (jlong)tokenLen;
        (*env)->SetLongArrayRegion(env, scidLenArr, 0, 1, &sJ);
        (*env)->SetLongArrayRegion(env, dcidLenArr, 0, 1, &dJ);
        (*env)->SetLongArrayRegion(env, tokenLenArr, 0, 1, &tJl);
    }
    return (jint)rc;
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
    if (fromLen == 0 || toLen == 0) return -6; /* QUICHE_ERR_INVALID_STATE (-1 = DONE would silent-drop) */
    quiche_recv_info info = {
        .from = (struct sockaddr *)&from, .from_len = fromLen,
        .to = (struct sockaddr *)&to, .to_len = toLen,
    };
    jbyte *buf = (*env)->GetByteArrayElements(env, bufArr, NULL);
    ssize_t rc = quiche_conn_recv(
        (quiche_conn *)(intptr_t)conn, (uint8_t *)buf, (size_t)bufLen, &info);
    (*env)->ReleaseByteArrayElements(env, bufArr, buf, JNI_ABORT);
    return (jlong)rc;
}

JNIEXPORT jlong JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connSend(
        JNIEnv *env, jclass cls, jlong conn,
        jbyteArray outArr, jint outLen) {
    UNUSED(cls);
    /* We ignore send_info for now (no path migration). Allocate on stack. */
    quiche_send_info info;
    memset(&info, 0, sizeof(info));
    jbyte *out = (*env)->GetByteArrayElements(env, outArr, NULL);
    ssize_t rc = quiche_conn_send(
        (quiche_conn *)(intptr_t)conn, (uint8_t *)out, (size_t)outLen, &info);
    (*env)->ReleaseByteArrayElements(env, outArr, out, 0); /* commit */
    return (jlong)rc;
}

JNIEXPORT jint JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connClose(
        JNIEnv *env, jclass cls, jlong conn,
        jboolean app, jlong err, jbyteArray reasonArr) {
    UNUSED(cls);
    jsize len = (reasonArr != NULL) ? (*env)->GetArrayLength(env, reasonArr) : 0;
    jbyte *reason = (len > 0)
        ? (*env)->GetByteArrayElements(env, reasonArr, NULL) : NULL;
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
    jbyte *out = (*env)->GetByteArrayElements(env, outArr, NULL);
    bool fin = false;
    uint64_t err = 0;
    ssize_t rc = quiche_conn_stream_recv(
        (quiche_conn *)(intptr_t)conn, (uint64_t)streamId,
        (uint8_t *)out, (size_t)outLen, &fin, &err);
    (*env)->ReleaseByteArrayElements(env, outArr, out, 0);
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
    jbyte *buf = (*env)->GetByteArrayElements(env, bufArr, NULL);
    uint64_t err = 0;
    ssize_t rc = quiche_conn_stream_send(
        (quiche_conn *)(intptr_t)conn, (uint64_t)streamId,
        (const uint8_t *)(buf + off), (size_t)len,
        fin == JNI_TRUE, &err);
    (*env)->ReleaseByteArrayElements(env, bufArr, buf, JNI_ABORT);
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

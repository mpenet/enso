/*
 * ABOUTME: JNI shim over cloudflare/libquiche plus the UDP socket I/O of Enso's HTTP/3 layer:
 * ABOUTME: batched receive/send on direct buffers, wake-up pipes and poll for the event loops.
 *
 * Conventions:
 *   - Every entry point is a package-private native of
 *     com.s_exp.enso.quiche.Quiche; Java wraps the raw handles (jlong
 *     pointers, int file descriptors) in state-checked objects and never
 *     exposes them.
 *   - Datagrams, socket addresses and per-call results travel in direct
 *     memory: Java's NativeBuffer resolves a direct buffer's address once
 *     (bufferAddress) and passes (address, capacity) with every call, which
 *     the shim range-checks before forming any pointer. The per-packet path
 *     makes no JNI lookup or array call and holds no critical region:
 *     quiche_conn_recv (which runs the TLS handshake, about 1 ms of signing
 *     with an RSA key) reads the datagram straight from the receive slab.
 *   - Stream payloads are Java byte[] accessed with GetPrimitiveArrayCritical:
 *     the region spans exactly one quiche call (a memcpy into or out of the
 *     stream buffers; quiche never calls back into the JVM and blocks on
 *     nothing a Java thread holds), and no other JNI function is called
 *     while it is open.
 *   - Cold-path byte[] arguments (connection ids, tokens, reasons) are
 *     copied with Get*ArrayRegion into bounded stack buffers; a failed
 *     copy (too long, or an exception pending) returns at once, before
 *     any further JNI call.
 *   - Every offset/length pair is checked against the buffer it indexes
 *     before any pointer is formed; violations return
 *     SHIM_ERR_INVALID_ARGUMENT, outside quiche's error range.
 *   - Socket addresses use a fixed 24-byte record (ADDR_*), written and
 *     read in native byte order, so the layout of sockaddr_storage never
 *     crosses the boundary:
 *       0 u8 family (0 none, 4 IPv4, 6 IPv6), 2 u16 port, 4 u32 IPv6 scope
 *       id, 8 16-byte address (IPv4 uses the first 4).
 */

#if defined(__linux__)
#define _GNU_SOURCE
#endif

#include <jni.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/types.h>

#if defined(__linux__)
#include <linux/filter.h>
#include <sys/eventfd.h>
#endif

#include <quiche.h>

#define UNUSED(x) (void)(x)

/* The JNI contract: bumped whenever a native's name, signature or a record
 * layout changes. Mirrored by Quiche.SHIM_ABI, checked when Java loads
 * the shim, so a stale build is refused instead of misread. */
#define ENSO_SHIM_ABI 3

/* Shim-detected bad arguments (bounds, address). Distinct from every
 * quiche_error value; mirrored by Quiche.SHIM_ERR_INVALID_ARGUMENT. */
#define SHIM_ERR_INVALID_ARGUMENT (-10000)

#define ADDR_LEN 24
#define ADDR_FAMILY 0
#define ADDR_PORT 2
#define ADDR_SCOPE 4
#define ADDR_IP 8

/* Receive metadata per datagram slot. */
#define RECV_META_LEN 64
#define RECV_LEN 0
#define RECV_FLAGS 4
#define RECV_PEER 8
#define RECV_LOCAL 32
#define RECV_FLAG_TRUNCATED 1

/* Send records: a 64-byte status header, then one record per datagram. */
#define SEND_HEADER_LEN 64
#define SEND_STATUS_DROPPED 0
#define SEND_STATUS_ERRNO 4
#define SEND_STATUS_FLAGS 8
#define SEND_STATUS_GSO_DISABLED 1
#define SEND_META_LEN 64
#define SEND_OFF 0
#define SEND_LEN 4
#define SEND_TO 8
#define SEND_FROM 32

/* connSend result record: shaped like a SEND record (offset and length
 * at 0 and 4 are the caller's), so quiche's destination and source land
 * straight in the send batch. */
#define PKT_TO SEND_TO
#define PKT_FROM SEND_FROM
#define PKT_DELAY 56
#define PKT_META_LEN SEND_META_LEN

/* headerInfo result record. */
#define HDR_VERSION 0
#define HDR_TYPE 4
#define HDR_SCID_LEN 5
#define HDR_DCID_LEN 6
#define HDR_TOKEN_LEN 8
#define HDR_SCID 12
#define HDR_DCID 32
#define HDR_TOKEN 52
#define HDR_MAX_TOKEN 1024
#define HDR_LEN (HDR_TOKEN + HDR_MAX_TOKEN)

/* udpOpen flags. */
#define UDP_OPEN_REUSEPORT 1
#define UDP_OPEN_PKTINFO 2

/* udpSendBatch flags. */
#define UDP_SEND_GSO 1
#define UDP_SEND_PKTINFO 2

/* poll result bits. */
#define POLL_READABLE 1
#define POLL_WAKE 2
#define POLL_WRITABLE 4

#define MAX_BATCH 64
#define MAX_REASON 1024
#define MAX_TOKEN 1024
#define MAX_GSO_SEGMENTS 64
#define MAX_GSO_BYTES 65000

/* The records nest as the code below assumes: each field inside its
 * record, the connection id slots wide enough for quiche's longest. */
_Static_assert(ADDR_IP + 16 <= ADDR_LEN, "ADDR address");
_Static_assert(RECV_PEER + ADDR_LEN <= RECV_LOCAL && RECV_LOCAL + ADDR_LEN <= RECV_META_LEN, "RECV addresses");
_Static_assert(SEND_TO + ADDR_LEN <= SEND_FROM && SEND_FROM + ADDR_LEN <= PKT_DELAY, "SEND addresses");
_Static_assert(PKT_DELAY + 8 <= SEND_META_LEN && SEND_STATUS_FLAGS + 4 <= SEND_HEADER_LEN, "SEND record");
_Static_assert(HDR_SCID + QUICHE_MAX_CONN_ID_LEN <= HDR_DCID && HDR_DCID + QUICHE_MAX_CONN_ID_LEN <= HDR_TOKEN,
               "HDR connection ids");

/* What Java must agree on, in the order of Quiche.LAYOUT_NAMES; compared
 * when the shim is loaded (Quiche.requireLayout). */
static const jint LAYOUT[] = {
    ADDR_LEN, ADDR_FAMILY, ADDR_PORT, ADDR_SCOPE, ADDR_IP,
    RECV_META_LEN, RECV_LEN, RECV_FLAGS, RECV_PEER, RECV_LOCAL, RECV_FLAG_TRUNCATED,
    SEND_HEADER_LEN, SEND_STATUS_DROPPED, SEND_STATUS_ERRNO, SEND_STATUS_FLAGS,
    SEND_STATUS_GSO_DISABLED, SEND_META_LEN, SEND_OFF, SEND_LEN, SEND_TO, SEND_FROM,
    PKT_DELAY,
    HDR_VERSION, HDR_TYPE, HDR_SCID_LEN, HDR_DCID_LEN, HDR_TOKEN_LEN, HDR_SCID, HDR_DCID,
    HDR_TOKEN, HDR_MAX_TOKEN, HDR_LEN,
    UDP_OPEN_REUSEPORT, UDP_OPEN_PKTINFO, UDP_SEND_GSO, UDP_SEND_PKTINFO,
    POLL_READABLE, POLL_WAKE, POLL_WRITABLE,
    QUICHE_MAX_CONN_ID_LEN, SHIM_ERR_INVALID_ARGUMENT,
};

#if defined(__linux__) && !defined(UDP_SEGMENT)
#define UDP_SEGMENT 103
#endif

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

/* Pointer to [off, off + len) of the native memory (addr, cap), or NULL
 * when the range is out of bounds. */
static uint8_t *mem_range(jlong addr, jint cap, jint off, jlong len) {
    if (addr == 0 || cap < 0 || off < 0 || len < 0) return NULL;
    if ((jlong)off + len > (jlong)cap) return NULL;
    return (uint8_t *)(intptr_t)addr + off;
}

static void put_u16(uint8_t *p, uint16_t v) { memcpy(p, &v, sizeof v); }
static void put_u32(uint8_t *p, uint32_t v) { memcpy(p, &v, sizeof v); }
static void put_i32(uint8_t *p, int32_t v) { memcpy(p, &v, sizeof v); }
static void put_i64(uint8_t *p, int64_t v) { memcpy(p, &v, sizeof v); }
static uint16_t get_u16(const uint8_t *p) { uint16_t v; memcpy(&v, p, sizeof v); return v; }
static uint32_t get_u32(const uint8_t *p) { uint32_t v; memcpy(&v, p, sizeof v); return v; }
static int32_t get_i32(const uint8_t *p) { int32_t v; memcpy(&v, p, sizeof v); return v; }

/* Encodes a sockaddr into an ADDR record; unknown families become 0. */
static void addr_put(uint8_t *rec, const struct sockaddr *sa) {
    memset(rec, 0, ADDR_LEN);
    if (sa == NULL) return;
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;
        rec[ADDR_FAMILY] = 4;
        put_u16(rec + ADDR_PORT, ntohs(sin->sin_port));
        memcpy(rec + ADDR_IP, &sin->sin_addr, 4);
    } else if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)sa;
        rec[ADDR_FAMILY] = 6;
        put_u16(rec + ADDR_PORT, ntohs(sin6->sin6_port));
        put_u32(rec + ADDR_SCOPE, sin6->sin6_scope_id);
        memcpy(rec + ADDR_IP, &sin6->sin6_addr, 16);
    }
}

/* Builds a sockaddr from an ADDR record. Returns its length, 0 when the
 * record holds no address. */
static socklen_t addr_get(const uint8_t *rec, struct sockaddr_storage *out) {
    memset(out, 0, sizeof *out);
    if (rec[ADDR_FAMILY] == 4) {
        struct sockaddr_in *sin = (struct sockaddr_in *)out;
        sin->sin_family = AF_INET;
        sin->sin_port = htons(get_u16(rec + ADDR_PORT));
        memcpy(&sin->sin_addr, rec + ADDR_IP, 4);
#if defined(__APPLE__)
        sin->sin_len = sizeof *sin;
#endif
        return (socklen_t)sizeof *sin;
    }
    if (rec[ADDR_FAMILY] == 6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)out;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(get_u16(rec + ADDR_PORT));
        sin6->sin6_scope_id = get_u32(rec + ADDR_SCOPE);
        memcpy(&sin6->sin6_addr, rec + ADDR_IP, 16);
#if defined(__APPLE__)
        sin6->sin6_len = sizeof *sin6;
#endif
        return (socklen_t)sizeof *sin6;
    }
    return 0;
}

/* Copies a byte[] of at most max bytes into dst. Returns its length, or -1
 * when it is too long or the copy raised an exception. A null array is
 * length 0. */
static jint copy_bytes(JNIEnv *env, jbyteArray arr, uint8_t *dst, jint max) {
    if (arr == NULL) return 0;
    jsize len = (*env)->GetArrayLength(env, arr);
    if (len < 0 || len > max) return -1;
    (*env)->GetByteArrayRegion(env, arr, 0, len, (jbyte *)dst);
    if ((*env)->ExceptionCheck(env)) return -1;
    return len;
}

static int set_nonblocking(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    if (fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) return -1;
    return fcntl(fd, F_SETFD, FD_CLOEXEC);
}

/* ------------------------------------------------------------------ */
/* Version                                                              */
/* ------------------------------------------------------------------ */

JNIEXPORT jstring JNICALL
Java_com_s_1exp_enso_quiche_Quiche_version(JNIEnv *env, jclass cls) {
    UNUSED(cls);
    return (*env)->NewStringUTF(env, quiche_version());
}

JNIEXPORT jint JNICALL
Java_com_s_1exp_enso_quiche_Quiche_shimAbi(JNIEnv *env, jclass cls) {
    UNUSED(env); UNUSED(cls);
    return ENSO_SHIM_ABI;
}

/* The LAYOUT table as an int[], or null when it can't be allocated. */
JNIEXPORT jintArray JNICALL
Java_com_s_1exp_enso_quiche_Quiche_layout(JNIEnv *env, jclass cls) {
    UNUSED(cls);
    jsize n = (jsize)(sizeof LAYOUT / sizeof LAYOUT[0]);
    jintArray a = (*env)->NewIntArray(env, n);
    if (a == NULL) return NULL;
    (*env)->SetIntArrayRegion(env, a, 0, n, LAYOUT);
    return a;
}

/* Address of a direct buffer's memory, 0 for a heap buffer. Called once
 * per buffer by NativeBuffer. */
JNIEXPORT jlong JNICALL
Java_com_s_1exp_enso_quiche_Quiche_bufferAddress(JNIEnv *env, jclass cls, jobject buf) {
    UNUSED(cls);
    if (buf == NULL) return 0;
    void *a = (*env)->GetDirectBufferAddress(env, buf);
    return (jlong)(intptr_t)a;
}

/* ------------------------------------------------------------------ */
/* Config                                                               */
/* ------------------------------------------------------------------ */

JNIEXPORT jlong JNICALL
Java_com_s_1exp_enso_quiche_Quiche_configNew(JNIEnv *env, jclass cls, jint version) {
    UNUSED(env); UNUSED(cls);
    return (jlong)(intptr_t)quiche_config_new((uint32_t)version);
}

JNIEXPORT void JNICALL
Java_com_s_1exp_enso_quiche_Quiche_configFree(JNIEnv *env, jclass cls, jlong config) {
    UNUSED(env); UNUSED(cls);
    if (config != 0) quiche_config_free((quiche_config *)(intptr_t)config);
}

static jint config_load(JNIEnv *env, jlong config, jstring path, bool chain) {
    if (config == 0 || path == NULL) return SHIM_ERR_INVALID_ARGUMENT;
    const char *p = (*env)->GetStringUTFChars(env, path, NULL);
    if (p == NULL) return SHIM_ERR_INVALID_ARGUMENT;
    int rc = chain
        ? quiche_config_load_cert_chain_from_pem_file((quiche_config *)(intptr_t)config, p)
        : quiche_config_load_priv_key_from_pem_file((quiche_config *)(intptr_t)config, p);
    (*env)->ReleaseStringUTFChars(env, path, p);
    return (jint)rc;
}

JNIEXPORT jint JNICALL
Java_com_s_1exp_enso_quiche_Quiche_configLoadCertChainFromPemFile(
        JNIEnv *env, jclass cls, jlong config, jstring path) {
    UNUSED(cls);
    return config_load(env, config, path, true);
}

JNIEXPORT jint JNICALL
Java_com_s_1exp_enso_quiche_Quiche_configLoadPrivKeyFromPemFile(
        JNIEnv *env, jclass cls, jlong config, jstring path) {
    UNUSED(cls);
    return config_load(env, config, path, false);
}

JNIEXPORT jint JNICALL
Java_com_s_1exp_enso_quiche_Quiche_configSetApplicationProtos(
        JNIEnv *env, jclass cls, jlong config, jbyteArray protos) {
    UNUSED(cls);
    uint8_t buf[256];
    jint len = copy_bytes(env, protos, buf, (jint)sizeof buf);
    if (config == 0 || len < 0) return SHIM_ERR_INVALID_ARGUMENT;
    return (jint)quiche_config_set_application_protos(
        (quiche_config *)(intptr_t)config, buf, (size_t)len);
}

#define CONFIG_SET_U64(name, cname)                                         \
JNIEXPORT void JNICALL                                                      \
Java_com_s_1exp_enso_quiche_Quiche_##name(JNIEnv *env, jclass cls,          \
                                          jlong config, jlong v) {          \
    UNUSED(env); UNUSED(cls);                                               \
    if (config != 0 && v >= 0) cname((quiche_config *)(intptr_t)config, (uint64_t)v); \
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
CONFIG_SET_U64(configSetMaxConnectionWindow, quiche_config_set_max_connection_window)
CONFIG_SET_U64(configSetMaxStreamWindow, quiche_config_set_max_stream_window)

JNIEXPORT void JNICALL
Java_com_s_1exp_enso_quiche_Quiche_configSetDisableActiveMigration(
        JNIEnv *env, jclass cls, jlong config, jboolean v) {
    UNUSED(env); UNUSED(cls);
    if (config != 0) {
        quiche_config_set_disable_active_migration((quiche_config *)(intptr_t)config, v == JNI_TRUE);
    }
}

JNIEXPORT void JNICALL
Java_com_s_1exp_enso_quiche_Quiche_configVerifyPeer(
        JNIEnv *env, jclass cls, jlong config, jboolean v) {
    UNUSED(env); UNUSED(cls);
    if (config != 0) quiche_config_verify_peer((quiche_config *)(intptr_t)config, v == JNI_TRUE);
}

/* ------------------------------------------------------------------ */
/* Accept / connect / retry / header parsing                            */
/* ------------------------------------------------------------------ */

JNIEXPORT jlong JNICALL
Java_com_s_1exp_enso_quiche_Quiche_accept(
        JNIEnv *env, jclass cls,
        jbyteArray scidArr, jbyteArray odcidArr,
        jlong addrs, jint addrsCap, jint localOff, jint peerOff, jlong config) {
    UNUSED(cls);
    uint8_t scid[QUICHE_MAX_CONN_ID_LEN], odcid[QUICHE_MAX_CONN_ID_LEN];
    jint scidLen = copy_bytes(env, scidArr, scid, QUICHE_MAX_CONN_ID_LEN);
    if (scidLen <= 0) return 0;
    /* odcid is null when no stateless retry happened: quiche then omits
     * retry_source_connection_id from its transport parameters, which a
     * client would otherwise reject (RFC 9000 §7.3). */
    jint odcidLen = copy_bytes(env, odcidArr, odcid, QUICHE_MAX_CONN_ID_LEN);
    if (odcidLen < 0) return 0;
    uint8_t *local = mem_range(addrs, addrsCap, localOff, ADDR_LEN);
    uint8_t *peer = mem_range(addrs, addrsCap, peerOff, ADDR_LEN);
    if (config == 0 || local == NULL || peer == NULL) return 0;
    struct sockaddr_storage l, p;
    socklen_t ll = addr_get(local, &l), pl = addr_get(peer, &p);
    if (ll == 0 || pl == 0) return 0;
    quiche_conn *conn = quiche_accept(scid, (size_t)scidLen,
                                      odcidArr == NULL ? NULL : odcid, (size_t)odcidLen,
                                      (struct sockaddr *)&l, ll, (struct sockaddr *)&p, pl,
                                      (quiche_config *)(intptr_t)config);
    return (jlong)(intptr_t)conn;
}

/* Client-side connection; the test suite drives the server with it. */
JNIEXPORT jlong JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connect(
        JNIEnv *env, jclass cls, jstring serverName, jbyteArray scidArr,
        jlong addrs, jint addrsCap, jint localOff, jint peerOff, jlong config) {
    UNUSED(cls);
    uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
    jint scidLen = copy_bytes(env, scidArr, scid, QUICHE_MAX_CONN_ID_LEN);
    if (scidLen <= 0) return 0;
    uint8_t *local = mem_range(addrs, addrsCap, localOff, ADDR_LEN);
    uint8_t *peer = mem_range(addrs, addrsCap, peerOff, ADDR_LEN);
    if (config == 0 || serverName == NULL || local == NULL || peer == NULL) return 0;
    struct sockaddr_storage l, p;
    socklen_t ll = addr_get(local, &l), pl = addr_get(peer, &p);
    if (ll == 0 || pl == 0) return 0;
    const char *name = (*env)->GetStringUTFChars(env, serverName, NULL);
    if (name == NULL) return 0;
    quiche_conn *conn = quiche_connect(name, scid, (size_t)scidLen,
                                       (struct sockaddr *)&l, ll, (struct sockaddr *)&p, pl,
                                       (quiche_config *)(intptr_t)config);
    (*env)->ReleaseStringUTFChars(env, serverName, name);
    return (jlong)(intptr_t)conn;
}

JNIEXPORT jlong JNICALL
Java_com_s_1exp_enso_quiche_Quiche_retry(
        JNIEnv *env, jclass cls,
        jbyteArray scidArr, jbyteArray dcidArr, jbyteArray newScidArr, jbyteArray tokenArr,
        jint version, jlong out, jint outCap, jint off, jint cap) {
    UNUSED(cls);
    uint8_t scid[QUICHE_MAX_CONN_ID_LEN], dcid[QUICHE_MAX_CONN_ID_LEN];
    uint8_t newScid[QUICHE_MAX_CONN_ID_LEN], token[MAX_TOKEN];
    jint scidLen = copy_bytes(env, scidArr, scid, QUICHE_MAX_CONN_ID_LEN);
    if (scidLen < 0) return SHIM_ERR_INVALID_ARGUMENT;
    jint dcidLen = copy_bytes(env, dcidArr, dcid, QUICHE_MAX_CONN_ID_LEN);
    if (dcidLen < 0) return SHIM_ERR_INVALID_ARGUMENT;
    jint newLen = copy_bytes(env, newScidArr, newScid, QUICHE_MAX_CONN_ID_LEN);
    if (newLen <= 0) return SHIM_ERR_INVALID_ARGUMENT;
    jint tokLen = copy_bytes(env, tokenArr, token, MAX_TOKEN);
    if (tokLen < 0) return SHIM_ERR_INVALID_ARGUMENT;
    uint8_t *dst = mem_range(out, outCap, off, cap);
    if (dst == NULL) return SHIM_ERR_INVALID_ARGUMENT;
    return (jlong)quiche_retry(scid, (size_t)scidLen, dcid, (size_t)dcidLen,
                               newScid, (size_t)newLen, token, (size_t)tokLen,
                               (uint32_t)version, dst, (size_t)cap);
}

/* Parses the QUIC header of buf[off, off + len) into the HDR record at
 * out[outOff]. Returns 0, or a negative quiche / shim error. */
JNIEXPORT jint JNICALL
Java_com_s_1exp_enso_quiche_Quiche_headerInfo(
        JNIEnv *env, jclass cls, jlong buf, jint bufCap, jint off, jint len, jint dcil,
        jlong out, jint outCap, jint outOff) {
    UNUSED(env); UNUSED(cls);
    uint8_t *pkt = mem_range(buf, bufCap, off, len);
    uint8_t *rec = mem_range(out, outCap, outOff, HDR_LEN);
    if (pkt == NULL || rec == NULL || dcil < 0 || dcil > QUICHE_MAX_CONN_ID_LEN) {
        return SHIM_ERR_INVALID_ARGUMENT;
    }
    uint32_t version = 0;
    uint8_t type = 0;
    size_t scidLen = QUICHE_MAX_CONN_ID_LEN, dcidLen = QUICHE_MAX_CONN_ID_LEN;
    size_t tokenLen = HDR_MAX_TOKEN;
    int rc = quiche_header_info(pkt, (size_t)len, (size_t)dcil, &version, &type,
                                rec + HDR_SCID, &scidLen, rec + HDR_DCID, &dcidLen,
                                rec + HDR_TOKEN, &tokenLen);
    if (rc < 0) return (jint)rc;
    put_i32(rec + HDR_VERSION, (int32_t)version);
    rec[HDR_TYPE] = type;
    rec[HDR_SCID_LEN] = (uint8_t)scidLen;
    rec[HDR_DCID_LEN] = (uint8_t)dcidLen;
    put_i32(rec + HDR_TOKEN_LEN, (int32_t)tokenLen);
    return 0;
}

JNIEXPORT jboolean JNICALL
Java_com_s_1exp_enso_quiche_Quiche_versionIsSupported(JNIEnv *env, jclass cls, jint version) {
    UNUSED(env); UNUSED(cls);
    return quiche_version_is_supported((uint32_t)version) ? JNI_TRUE : JNI_FALSE;
}

/* ------------------------------------------------------------------ */
/* Connection                                                           */
/* ------------------------------------------------------------------ */

#define CONN(c) ((quiche_conn *)(intptr_t)(c))

JNIEXPORT void JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connFree(JNIEnv *env, jclass cls, jlong conn) {
    UNUSED(env); UNUSED(cls);
    if (conn != 0) quiche_conn_free(CONN(conn));
}

JNIEXPORT jboolean JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connIsClosed(JNIEnv *env, jclass cls, jlong conn) {
    UNUSED(env); UNUSED(cls);
    return quiche_conn_is_closed(CONN(conn)) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connIsEstablished(JNIEnv *env, jclass cls, jlong conn) {
    UNUSED(env); UNUSED(cls);
    return quiche_conn_is_established(CONN(conn)) ? JNI_TRUE : JNI_FALSE;
}

/* Nanoseconds until quiche's next timeout, or -1 when none is armed. */
JNIEXPORT jlong JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connTimeoutAsNanos(JNIEnv *env, jclass cls, jlong conn) {
    UNUSED(env); UNUSED(cls);
    uint64_t v = quiche_conn_timeout_as_nanos(CONN(conn));
    if (v > (uint64_t)INT64_MAX) return -1;
    return (jlong)v;
}

/* -2 once the connection is closed, else as connTimeoutAsNanos. */
JNIEXPORT jlong JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connTimeoutAsNanosOrClosed(JNIEnv *env, jclass cls, jlong conn) {
    UNUSED(env); UNUSED(cls);
    if (quiche_conn_is_closed(CONN(conn))) return -2;
    uint64_t v = quiche_conn_timeout_as_nanos(CONN(conn));
    if (v > (uint64_t)INT64_MAX) return -1;
    return (jlong)v;
}

JNIEXPORT void JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connOnTimeout(JNIEnv *env, jclass cls, jlong conn) {
    UNUSED(env); UNUSED(cls);
    quiche_conn_on_timeout(CONN(conn));
}

/* out = {1 when the peer's CONNECTION_CLOSE was application level, its
 * error code}; false when the peer has not closed the connection. */
JNIEXPORT jboolean JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connPeerError(
        JNIEnv *env, jclass cls, jlong conn, jlongArray out) {
    UNUSED(cls);
    if (out == NULL || (*env)->GetArrayLength(env, out) < 2) return JNI_FALSE;
    bool isApp = false;
    uint64_t code = 0;
    const uint8_t *reason = NULL;
    size_t reasonLen = 0;
    if (!quiche_conn_peer_error(CONN(conn), &isApp, &code, &reason, &reasonLen)) {
        return JNI_FALSE;
    }
    jlong vals[2] = { isApp ? 1 : 0, (jlong)code };
    (*env)->SetLongArrayRegion(env, out, 0, 2, vals);
    return (*env)->ExceptionCheck(env) ? JNI_FALSE : JNI_TRUE;
}

/* out = {1 when our queued or sent CONNECTION_CLOSE is application level,
 * its error code}; false when we have not closed the connection. */
JNIEXPORT jboolean JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connLocalError(
        JNIEnv *env, jclass cls, jlong conn, jlongArray out) {
    UNUSED(cls);
    if (out == NULL || (*env)->GetArrayLength(env, out) < 2) return JNI_FALSE;
    bool isApp = false;
    uint64_t code = 0;
    const uint8_t *reason = NULL;
    size_t reasonLen = 0;
    if (!quiche_conn_local_error(CONN(conn), &isApp, &code, &reason, &reasonLen)) {
        return JNI_FALSE;
    }
    jlong vals[2] = { isApp ? 1 : 0, (jlong)code };
    (*env)->SetLongArrayRegion(env, out, 0, 2, vals);
    return (*env)->ExceptionCheck(env) ? JNI_FALSE : JNI_TRUE;
}

/* Feeds the datagram buf[off, off + len) to quiche, received from the
 * peer address record meta[peerOff] on the local record meta[localOff].
 * quiche decrypts in place; the receive slab is reused afterwards. */
JNIEXPORT jlong JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connRecv(
        JNIEnv *env, jclass cls, jlong conn, jlong buf, jint bufCap, jint off, jint len,
        jlong meta, jint metaCap, jint peerOff, jint localOff) {
    UNUSED(env); UNUSED(cls);
    uint8_t *pkt = mem_range(buf, bufCap, off, len);
    uint8_t *peer = mem_range(meta, metaCap, peerOff, ADDR_LEN);
    uint8_t *local = mem_range(meta, metaCap, localOff, ADDR_LEN);
    if (pkt == NULL || peer == NULL || local == NULL) return SHIM_ERR_INVALID_ARGUMENT;
    struct sockaddr_storage from, to;
    socklen_t fl = addr_get(peer, &from), tl = addr_get(local, &to);
    if (fl == 0 || tl == 0) return SHIM_ERR_INVALID_ARGUMENT;
    quiche_recv_info info = {
        .from = (struct sockaddr *)&from, .from_len = fl,
        .to = (struct sockaddr *)&to, .to_len = tl,
    };
    return (jlong)quiche_conn_recv(CONN(conn), pkt, (size_t)len, &info);
}

static int64_t delay_until(const struct timespec *at) {
    if (at->tv_sec == 0 && at->tv_nsec == 0) return 0;
#if defined(__linux__)
    /* quiche's send_info.at is a CLOCK_MONOTONIC instant on Linux. */
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    int64_t d = ((int64_t)at->tv_sec - (int64_t)now.tv_sec) * 1000000000LL
        + ((int64_t)at->tv_nsec - (int64_t)now.tv_nsec);
    return d > 0 ? d : 0;
#else
    return 0;
#endif
}

/* Writes one packet into out[off, off + cap). On success the PKT record
 * at meta[metaOff] receives the destination, the local source address
 * and how many nanoseconds from now quiche's pacer wants it sent. */
JNIEXPORT jlong JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connSend(
        JNIEnv *env, jclass cls, jlong conn, jlong out, jint outCap, jint off, jint cap,
        jlong meta, jint metaCap, jint metaOff) {
    UNUSED(env); UNUSED(cls);
    uint8_t *dst = mem_range(out, outCap, off, cap);
    uint8_t *rec = mem_range(meta, metaCap, metaOff, PKT_META_LEN);
    if (dst == NULL || rec == NULL) return SHIM_ERR_INVALID_ARGUMENT;
    quiche_send_info info;
    memset(&info, 0, sizeof info);
    ssize_t rc = quiche_conn_send(CONN(conn), dst, (size_t)cap, &info);
    if (rc < 0) return (jlong)rc;
    addr_put(rec + PKT_TO, (struct sockaddr *)&info.to);
    addr_put(rec + PKT_FROM, (struct sockaddr *)&info.from);
    put_i64(rec + PKT_DELAY, delay_until(&info.at));
    return (jlong)rc;
}

JNIEXPORT jint JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connClose(
        JNIEnv *env, jclass cls, jlong conn, jboolean app, jlong err, jbyteArray reasonArr) {
    UNUSED(cls);
    uint8_t reason[MAX_REASON];
    jint len = copy_bytes(env, reasonArr, reason, MAX_REASON);
    if (len < 0) return SHIM_ERR_INVALID_ARGUMENT;
    return (jint)quiche_conn_close(CONN(conn), app == JNI_TRUE, (uint64_t)err, reason, (size_t)len);
}

JNIEXPORT jlong JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connSendAckEliciting(JNIEnv *env, jclass cls, jlong conn) {
    UNUSED(env); UNUSED(cls);
    return (jlong)quiche_conn_send_ack_eliciting(CONN(conn));
}

/* The active path's smoothed round-trip time estimate in nanoseconds, or
 * -1 when quiche has no path statistics. */
JNIEXPORT jlong JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connRttNanos(JNIEnv *env, jclass cls, jlong conn) {
    UNUSED(env); UNUSED(cls);
    quiche_path_stats stats;
    memset(&stats, 0, sizeof stats);
    if (quiche_conn_path_stats(CONN(conn), 0, &stats) != 0) return -1;
    if (stats.rtt > (uint64_t)INT64_MAX) return -1;
    return (jlong)stats.rtt;
}

/* Receive-window control on a live connection, added to libquiche by
 * native/enso_quiche/patches/ (absent from stock libquiche). Built against
 * the patched header (ENSO_QUICHE_RECV_WINDOW, set by the Makefile) the
 * calls are linked directly; otherwise they are looked up in the loaded
 * libquiche, so the shim still runs on a stock one, without them. */
typedef void (*set_max_window_fn)(quiche_conn *, uint64_t);
typedef uint64_t (*connection_window_fn)(const quiche_conn *);
static set_max_window_fn set_max_connection_window;
static connection_window_fn connection_window;

/* Whether libquiche offers receive-window control. Called once, when Java
 * loads the shim, before any connection exists. */
JNIEXPORT jboolean JNICALL
Java_com_s_1exp_enso_quiche_Quiche_recvWindowControl(JNIEnv *env, jclass cls) {
    UNUSED(env); UNUSED(cls);
#ifdef ENSO_QUICHE_RECV_WINDOW
    set_max_connection_window = quiche_conn_set_max_connection_window;
    connection_window = quiche_conn_connection_window;
#else
    set_max_connection_window = (set_max_window_fn)dlsym(RTLD_DEFAULT, "quiche_conn_set_max_connection_window");
    connection_window = (connection_window_fn)dlsym(RTLD_DEFAULT, "quiche_conn_connection_window");
#endif
    return set_max_connection_window != NULL && connection_window != NULL;
}

/* Raises the connection window's autotuning bound (never below the current
 * window); no-op without receive-window control. */
JNIEXPORT void JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connSetMaxConnectionWindow(JNIEnv *env, jclass cls, jlong conn, jlong v) {
    UNUSED(env); UNUSED(cls);
    if (set_max_connection_window != NULL && v >= 0) set_max_connection_window(CONN(conn), (uint64_t)v);
}

/* The current connection-level receive window, or -1 without receive-window
 * control. */
JNIEXPORT jlong JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connConnectionWindow(JNIEnv *env, jclass cls, jlong conn) {
    UNUSED(env); UNUSED(cls);
    if (connection_window == NULL) return -1;
    uint64_t w = connection_window(CONN(conn));
    return w > (uint64_t)INT64_MAX ? INT64_MAX : (jlong)w;
}

/* DER bytes of the peer's certificate, or null when it presented none. */
JNIEXPORT jbyteArray JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connPeerCert(JNIEnv *env, jclass cls, jlong conn) {
    UNUSED(cls);
    const uint8_t *der = NULL;
    size_t len = 0;
    quiche_conn_peer_cert(CONN(conn), &der, &len);
    if (der == NULL || len == 0 || len > (size_t)INT32_MAX) return NULL;
    jbyteArray out = (*env)->NewByteArray(env, (jsize)len);
    if (out == NULL) return NULL;
    (*env)->SetByteArrayRegion(env, out, 0, (jsize)len, (const jbyte *)der);
    return out;
}

/* ------------------------------------------------------------------ */
/* Streams                                                              */
/* ------------------------------------------------------------------ */

JNIEXPORT jlong JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connStreamCapacity(
        JNIEnv *env, jclass cls, jlong conn, jlong streamId) {
    UNUSED(env); UNUSED(cls);
    if (streamId < 0) return SHIM_ERR_INVALID_ARGUMENT;
    return (jlong)quiche_conn_stream_capacity(CONN(conn), (uint64_t)streamId);
}

/* A peer reset is returned as STREAM_RESET_BASE - code: below every
 * quiche and shim error, and carrying the peer's error code (< 2^62). */
#define STREAM_RESET_BASE (-(1LL << 62))

/* Reads into out[off, off + len). Returns (bytes << 1) | fin, the peer's
 * reset as STREAM_RESET_BASE - code, or another negative quiche error. */
JNIEXPORT jlong JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connStreamRecv(
        JNIEnv *env, jclass cls, jlong conn, jlong streamId,
        jbyteArray outArr, jint off, jint len) {
    UNUSED(cls);
    if (outArr == NULL || streamId < 0 || off < 0 || len < 0) return SHIM_ERR_INVALID_ARGUMENT;
    jsize arrLen = (*env)->GetArrayLength(env, outArr);
    if ((jlong)off + (jlong)len > (jlong)arrLen) return SHIM_ERR_INVALID_ARGUMENT;
    bool fin = false;
    uint64_t err = 0;
    uint8_t *out = (*env)->GetPrimitiveArrayCritical(env, outArr, NULL);
    if (out == NULL) return SHIM_ERR_INVALID_ARGUMENT;
    ssize_t rc = quiche_conn_stream_recv(CONN(conn), (uint64_t)streamId,
                                         out + off, (size_t)len, &fin, &err);
    (*env)->ReleasePrimitiveArrayCritical(env, outArr, out, 0);
    if (rc == QUICHE_ERR_STREAM_RESET) {
        return (jlong)(STREAM_RESET_BASE - (int64_t)(err & ((1ULL << 62) - 1)));
    }
    if (rc < 0) return (jlong)rc;
    return ((jlong)rc << 1) | (fin ? 1 : 0);
}

JNIEXPORT jlong JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connStreamSend(
        JNIEnv *env, jclass cls, jlong conn, jlong streamId,
        jbyteArray bufArr, jint off, jint len, jboolean fin) {
    UNUSED(cls);
    if (bufArr == NULL || streamId < 0 || off < 0 || len < 0) return SHIM_ERR_INVALID_ARGUMENT;
    jsize arrLen = (*env)->GetArrayLength(env, bufArr);
    if ((jlong)off + (jlong)len > (jlong)arrLen) return SHIM_ERR_INVALID_ARGUMENT;
    uint64_t err = 0;
    uint8_t *buf = (*env)->GetPrimitiveArrayCritical(env, bufArr, NULL);
    if (buf == NULL) return SHIM_ERR_INVALID_ARGUMENT;
    ssize_t rc = quiche_conn_stream_send(CONN(conn), (uint64_t)streamId,
                                         buf + off, (size_t)len, fin == JNI_TRUE, &err);
    (*env)->ReleasePrimitiveArrayCritical(env, bufArr, buf, JNI_ABORT);
    return (jlong)rc;
}

JNIEXPORT jint JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connStreamShutdown(
        JNIEnv *env, jclass cls, jlong conn, jlong streamId, jint direction, jlong err) {
    UNUSED(env); UNUSED(cls);
    if (streamId < 0 || (direction != QUICHE_SHUTDOWN_READ && direction != QUICHE_SHUTDOWN_WRITE)) {
        return SHIM_ERR_INVALID_ARGUMENT;
    }
    return (jint)quiche_conn_stream_shutdown(CONN(conn), (uint64_t)streamId,
                                             (enum quiche_shutdown)direction, (uint64_t)err);
}

JNIEXPORT jlong JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connStreamReadableNext(JNIEnv *env, jclass cls, jlong conn) {
    UNUSED(env); UNUSED(cls);
    return (jlong)quiche_conn_stream_readable_next(CONN(conn));
}

JNIEXPORT jlong JNICALL
Java_com_s_1exp_enso_quiche_Quiche_connStreamWritableNext(JNIEnv *env, jclass cls, jlong conn) {
    UNUSED(env); UNUSED(cls);
    return (jlong)quiche_conn_stream_writable_next(CONN(conn));
}

/* ------------------------------------------------------------------ */
/* UDP sockets                                                          */
/* ------------------------------------------------------------------ */

/* Best effort: the largest size up to `bytes` the OS accepts. On Linux
 * the FORCE variant first, which passes net.core.rmem_max / wmem_max for a
 * process with CAP_NET_ADMIN (root in a container, a granted capability);
 * otherwise the plain option, which Linux clamps silently and macOS
 * refuses above kern.ipc.maxsockbuf (hence the halving). */
static void set_buffer(int fd, int opt, int bytes) {
#if defined(__linux__) && defined(SO_RCVBUFFORCE) && defined(SO_SNDBUFFORCE)
    int force = opt == SO_RCVBUF ? SO_RCVBUFFORCE : SO_SNDBUFFORCE;
    if (setsockopt(fd, SOL_SOCKET, force, &bytes, sizeof bytes) == 0) return;
#endif
    for (int size = bytes; size >= 65536; size /= 2) {
        if (setsockopt(fd, SOL_SOCKET, opt, &size, sizeof size) == 0) return;
    }
}

/* Opens a non-blocking UDP socket bound to ip:port (4- or 16-byte ip).
 * Returns the fd, or -errno. */
JNIEXPORT jint JNICALL
Java_com_s_1exp_enso_quiche_Quiche_udpOpen(
        JNIEnv *env, jclass cls, jbyteArray ipArr, jint port, jint flags,
        jint rcvBuf, jint sndBuf) {
    UNUSED(cls);
    uint8_t ip[16];
    jint ipLen = copy_bytes(env, ipArr, ip, 16);
    if ((ipLen != 4 && ipLen != 16) || port < 0 || port > 65535) return -EINVAL;
    int family = ipLen == 4 ? AF_INET : AF_INET6;
#if defined(__linux__)
    /* Atomically: a fork/exec on another JVM thread between socket() and
     * fcntl() would otherwise inherit the descriptor. */
    int fd = socket(family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -errno;
#else
    int fd = socket(family, SOCK_DGRAM, 0);
    if (fd < 0) return -errno;
#endif
    int one = 1, zero = 0;
#if !defined(__linux__)
    if (set_nonblocking(fd) != 0) goto fail;
#endif
    if (family == AF_INET6 && setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof zero) != 0) {
        goto fail;
    }
    if (flags & UDP_OPEN_REUSEPORT) {
#if defined(SO_REUSEPORT)
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one) != 0) goto fail;
#else
        errno = ENOTSUP;
        goto fail;
#endif
    }
    if (rcvBuf > 0) set_buffer(fd, SO_RCVBUF, rcvBuf);
    if (sndBuf > 0) set_buffer(fd, SO_SNDBUF, sndBuf);
#if defined(__linux__)
    if (flags & UDP_OPEN_PKTINFO) {
        if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof one) != 0 && family == AF_INET) {
            goto fail;
        }
        if (family == AF_INET6
            && setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof one) != 0) {
            goto fail;
        }
    }
#endif
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof ss);
    socklen_t sl;
    if (family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
        sin->sin_family = AF_INET;
        sin->sin_port = htons((uint16_t)port);
        memcpy(&sin->sin_addr, ip, 4);
        sl = sizeof *sin;
    } else {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons((uint16_t)port);
        memcpy(&sin6->sin6_addr, ip, 16);
        sl = sizeof *sin6;
    }
#if defined(__APPLE__)
    ((struct sockaddr *)&ss)->sa_len = (uint8_t)sl;
#endif
    if (bind(fd, (struct sockaddr *)&ss, sl) != 0) goto fail;
    return fd;
fail:;
    int e = errno;
    close(fd);
    return -e;
}

JNIEXPORT jint JNICALL
Java_com_s_1exp_enso_quiche_Quiche_udpLocalAddress(
        JNIEnv *env, jclass cls, jint fd, jlong out, jint outCap, jint off) {
    UNUSED(env); UNUSED(cls);
    uint8_t *rec = mem_range(out, outCap, off, ADDR_LEN);
    if (rec == NULL || fd < 0) return SHIM_ERR_INVALID_ARGUMENT;
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    if (getsockname(fd, (struct sockaddr *)&ss, &sl) != 0) return -errno;
    addr_put(rec, (struct sockaddr *)&ss);
    return 0;
}

/* Effective SO_RCVBUF / SO_SNDBUF, or -errno. */
JNIEXPORT jint JNICALL
Java_com_s_1exp_enso_quiche_Quiche_udpBufferSize(JNIEnv *env, jclass cls, jint fd, jboolean send) {
    UNUSED(env); UNUSED(cls);
    int v = 0;
    socklen_t l = sizeof v;
    if (getsockopt(fd, SOL_SOCKET, send ? SO_SNDBUF : SO_RCVBUF, &v, &l) != 0) return -errno;
    return v;
}

JNIEXPORT jint JNICALL
Java_com_s_1exp_enso_quiche_Quiche_udpClose(JNIEnv *env, jclass cls, jint fd) {
    UNUSED(env); UNUSED(cls);
    if (fd < 0) return SHIM_ERR_INVALID_ARGUMENT;
    return close(fd) == 0 ? 0 : -errno;
}

/* Steers datagrams across the SO_REUSEPORT group of fd by the first byte
 * of their destination connection id, modulo n (offset 1 in a short
 * header, 6 in a long one): the server encodes the owning loop there. A
 * packet too short to read falls to socket 0; an index past the group
 * size falls back to the kernel's hash. Returns 0 or -errno (-ENOTSUP off
 * Linux). */
JNIEXPORT jint JNICALL
Java_com_s_1exp_enso_quiche_Quiche_udpAttachSteering(JNIEnv *env, jclass cls, jint fd, jint n) {
    UNUSED(env); UNUSED(cls);
#if defined(__linux__) && defined(SO_ATTACH_REUSEPORT_CBPF)
    if (n < 1 || n > 256) return -EINVAL;
    /* Socket index = first byte of the destination id (offset 1 in a short
     * header, 6 in a long one) modulo n. Initial and 0-RTT packets (long
     * header, type bit 0x20 clear) carry an id the client chose, which
     * must not pick the loop: they return n, an index out of range, so
     * the kernel falls back to its 4-tuple hash. */
    struct sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 0),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x80, 2, 0),
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 1),
        BPF_JUMP(BPF_JMP | BPF_JA, 3, 0, 0),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x20, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, (uint32_t)n),
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 6),
        BPF_STMT(BPF_ALU | BPF_MOD | BPF_K, (uint32_t)n),
        BPF_STMT(BPF_RET | BPF_A, 0),
    };
    struct sock_fprog prog = { .len = sizeof code / sizeof code[0], .filter = code };
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF, &prog, sizeof prog) != 0) return -errno;
    return 0;
#else
    UNUSED(fd); UNUSED(n);
    return -ENOTSUP;
#endif
}

#if defined(__linux__)
/* Writes the destination address of a received datagram (IP_PKTINFO /
 * IPV6_PKTINFO) into rec; leaves it untouched when absent. */
static void read_pktinfo(struct msghdr *msg, uint8_t *rec, uint16_t localPort) {
    for (struct cmsghdr *c = CMSG_FIRSTHDR(msg); c != NULL; c = CMSG_NXTHDR(msg, c)) {
        if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_PKTINFO) {
            struct in_pktinfo pi;
            memcpy(&pi, CMSG_DATA(c), sizeof pi);
            memset(rec, 0, ADDR_LEN);
            rec[ADDR_FAMILY] = 4;
            put_u16(rec + ADDR_PORT, localPort);
            memcpy(rec + ADDR_IP, &pi.ipi_addr, 4);
            return;
        }
        if (c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_PKTINFO) {
            struct in6_pktinfo pi;
            memcpy(&pi, CMSG_DATA(c), sizeof pi);
            memset(rec, 0, ADDR_LEN);
            rec[ADDR_FAMILY] = 6;
            put_u16(rec + ADDR_PORT, localPort);
            put_u32(rec + ADDR_SCOPE, (uint32_t)pi.ipi6_ifindex);
            memcpy(rec + ADDR_IP, &pi.ipi6_addr, 16);
            return;
        }
    }
}
#endif

#define CMSG_BUF 128

/* Receives up to maxSlots datagrams without blocking: datagram i lands in
 * slab[i * slotSize, ...) and its RECV record at meta[i * RECV_META_LEN].
 * The local address of each record starts as the template at
 * meta[maxSlots * RECV_META_LEN] (the bound address) and is replaced by
 * the packet's destination when IP_PKTINFO is on. Returns the count (0
 * when nothing is queued) or -errno. */
JNIEXPORT jint JNICALL
Java_com_s_1exp_enso_quiche_Quiche_udpRecvBatch(
        JNIEnv *env, jclass cls, jint fd, jlong slabAddr, jint slabCap, jint slotSize, jint maxSlots,
        jlong metaAddr, jint metaCap) {
    UNUSED(env); UNUSED(cls);
    if (fd < 0 || slotSize <= 0 || maxSlots <= 0 || maxSlots > MAX_BATCH) {
        return SHIM_ERR_INVALID_ARGUMENT;
    }
    uint8_t *slab = mem_range(slabAddr, slabCap, 0, (jlong)slotSize * maxSlots);
    uint8_t *meta = mem_range(metaAddr, metaCap, 0, (jlong)RECV_META_LEN * (maxSlots + 1));
    if (slab == NULL || meta == NULL) return SHIM_ERR_INVALID_ARGUMENT;
    const uint8_t *localTemplate = meta + (size_t)RECV_META_LEN * maxSlots;
    uint16_t localPort = get_u16(localTemplate + ADDR_PORT);
    struct sockaddr_storage names[MAX_BATCH];
    struct iovec iov[MAX_BATCH];
    union { struct cmsghdr align; uint8_t buf[CMSG_BUF]; } ctl[MAX_BATCH];
    int count = 0;
#if defined(__linux__)
    struct mmsghdr msgs[MAX_BATCH];
    memset(msgs, 0, sizeof(struct mmsghdr) * (size_t)maxSlots);
    for (int i = 0; i < maxSlots; i++) {
        iov[i].iov_base = slab + (size_t)i * slotSize;
        iov[i].iov_len = (size_t)slotSize;
        msgs[i].msg_hdr.msg_name = &names[i];
        msgs[i].msg_hdr.msg_namelen = sizeof names[i];
        msgs[i].msg_hdr.msg_iov = &iov[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_control = ctl[i].buf;
        msgs[i].msg_hdr.msg_controllen = CMSG_BUF;
    }
    int n;
    do {
        n = recvmmsg(fd, msgs, (unsigned)maxSlots, MSG_DONTWAIT, NULL);
    } while (n < 0 && errno == EINTR);
    if (n < 0) return (errno == EAGAIN || errno == EWOULDBLOCK) ? 0 : -errno;
    for (int i = 0; i < n; i++) {
        uint8_t *rec = meta + (size_t)i * RECV_META_LEN;
        put_i32(rec + RECV_LEN, (int32_t)msgs[i].msg_len);
        put_i32(rec + RECV_FLAGS, (msgs[i].msg_hdr.msg_flags & MSG_TRUNC) ? RECV_FLAG_TRUNCATED : 0);
        addr_put(rec + RECV_PEER, (struct sockaddr *)&names[i]);
        memcpy(rec + RECV_LOCAL, localTemplate, ADDR_LEN);
        read_pktinfo(&msgs[i].msg_hdr, rec + RECV_LOCAL, localPort);
    }
    count = n;
#else
    UNUSED(ctl);
    for (int i = 0; i < maxSlots; i++) {
        struct msghdr msg;
        memset(&msg, 0, sizeof msg);
        iov[i].iov_base = slab + (size_t)i * slotSize;
        iov[i].iov_len = (size_t)slotSize;
        msg.msg_name = &names[i];
        msg.msg_namelen = sizeof names[i];
        msg.msg_iov = &iov[i];
        msg.msg_iovlen = 1;
        ssize_t r;
        do {
            r = recvmsg(fd, &msg, MSG_DONTWAIT);
        } while (r < 0 && errno == EINTR);
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            if (count > 0) break;
            return -errno;
        }
        uint8_t *rec = meta + (size_t)i * RECV_META_LEN;
        put_i32(rec + RECV_LEN, (int32_t)r);
        put_i32(rec + RECV_FLAGS, (msg.msg_flags & MSG_TRUNC) ? RECV_FLAG_TRUNCATED : 0);
        addr_put(rec + RECV_PEER, (struct sockaddr *)&names[i]);
        memcpy(rec + RECV_LOCAL, localTemplate, ADDR_LEN);
        count++;
    }
#endif
    UNUSED(localPort);
    return count;
}

/* Fills msg for the packets of one send (a single datagram, or a GSO
 * train of segments of segSize bytes). cmsg receives the source address
 * (IP_PKTINFO) and the segment size. */
static void build_send(struct msghdr *msg, struct iovec *iov, struct sockaddr_storage *to,
                       socklen_t toLen, const uint8_t *fromRec, uint8_t *cbuf, size_t cbufLen,
                       uint8_t *data, size_t len, int segSize, int flags) {
    memset(msg, 0, sizeof *msg);
    iov->iov_base = data;
    iov->iov_len = len;
    msg->msg_name = to;
    msg->msg_namelen = toLen;
    msg->msg_iov = iov;
    msg->msg_iovlen = 1;
#if defined(__linux__)
    size_t used = 0;
    memset(cbuf, 0, cbufLen);
    msg->msg_control = cbuf;
    msg->msg_controllen = cbufLen;
    struct cmsghdr *c = CMSG_FIRSTHDR(msg);
    if ((flags & UDP_SEND_PKTINFO) && fromRec[ADDR_FAMILY] == 4 && to->ss_family == AF_INET) {
        struct in_pktinfo pi;
        memset(&pi, 0, sizeof pi);
        memcpy(&pi.ipi_spec_dst, fromRec + ADDR_IP, 4);
        c->cmsg_level = IPPROTO_IP;
        c->cmsg_type = IP_PKTINFO;
        c->cmsg_len = CMSG_LEN(sizeof pi);
        memcpy(CMSG_DATA(c), &pi, sizeof pi);
        used += CMSG_SPACE(sizeof pi);
        c = CMSG_NXTHDR(msg, c);
    } else if ((flags & UDP_SEND_PKTINFO) && fromRec[ADDR_FAMILY] == 6 && to->ss_family == AF_INET6) {
        struct in6_pktinfo pi;
        memset(&pi, 0, sizeof pi);
        memcpy(&pi.ipi6_addr, fromRec + ADDR_IP, 16);
        c->cmsg_level = IPPROTO_IPV6;
        c->cmsg_type = IPV6_PKTINFO;
        c->cmsg_len = CMSG_LEN(sizeof pi);
        memcpy(CMSG_DATA(c), &pi, sizeof pi);
        used += CMSG_SPACE(sizeof pi);
        c = CMSG_NXTHDR(msg, c);
    }
    if (segSize > 0 && c != NULL) {
        uint16_t seg = (uint16_t)segSize;
        c->cmsg_level = SOL_UDP;
        c->cmsg_type = UDP_SEGMENT;
        c->cmsg_len = CMSG_LEN(sizeof seg);
        memcpy(CMSG_DATA(c), &seg, sizeof seg);
        used += CMSG_SPACE(sizeof seg);
    }
    msg->msg_controllen = used;
    if (used == 0) msg->msg_control = NULL;
#else
    UNUSED(fromRec); UNUSED(cbuf); UNUSED(cbufLen); UNUSED(segSize); UNUSED(flags);
#endif
}

/* Errors after which the datagram is treated as lost and sending goes on:
 * transient buffer exhaustion, a firewall verdict, an ICMP-reported
 * unreachable peer, an oversized datagram. */
static bool send_error_is_loss(int e) {
    return e == ENOBUFS || e == ENOMEM || e == EPERM || e == EACCES || e == ECONNREFUSED
        || e == EHOSTUNREACH || e == ENETUNREACH || e == EHOSTDOWN || e == ENETDOWN
        || e == EMSGSIZE || e == EADDRNOTAVAIL || e == EINVAL || e == EIO;
}

/* Length of the run of SEND records starting at record i that go out as
 * one datagram send: 1, or with GSO the following records to the same
 * destination from the same source, contiguous in the slab and of equal
 * length (the last may be shorter), within the kernel's GSO limits. */
static int send_run(const uint8_t *meta, int i, int count, int flags) {
    int segs = 1;
#if defined(__linux__)
    if (flags & UDP_SEND_GSO) {
        const uint8_t *r = meta + SEND_HEADER_LEN + (size_t)i * SEND_META_LEN;
        int32_t off = get_i32(r + SEND_OFF), len = get_i32(r + SEND_LEN);
        size_t total = (size_t)len;
        while (i + segs < count && segs < MAX_GSO_SEGMENTS) {
            const uint8_t *nr = meta + SEND_HEADER_LEN + (size_t)(i + segs) * SEND_META_LEN;
            int32_t noff = get_i32(nr + SEND_OFF), nlen = get_i32(nr + SEND_LEN);
            if (noff != off + (int32_t)total || nlen > len || total + (size_t)nlen > MAX_GSO_BYTES
                || memcmp(nr + SEND_TO, r + SEND_TO, ADDR_LEN) != 0
                || memcmp(nr + SEND_FROM, r + SEND_FROM, ADDR_LEN) != 0) {
                break;
            }
            total += (size_t)nlen;
            segs++;
            if (nlen < len) break;
        }
    }
#else
    UNUSED(meta); UNUSED(i); UNUSED(count); UNUSED(flags);
#endif
    return segs;
}

/* Bytes of the records [i, i + segs). */
static size_t run_bytes(const uint8_t *meta, int i, int segs) {
    size_t total = 0;
    for (int k = 0; k < segs; k++) {
        total += (size_t)get_i32(meta + SEND_HEADER_LEN + (size_t)(i + k) * SEND_META_LEN + SEND_LEN);
    }
    return total;
}

/* Sends `count` SEND records of meta (after its status header) whose
 * payloads live in slab. Consecutive records to the same destination from
 * the same source, contiguous in the slab and of equal length (the last
 * may be shorter) go out as one GSO send when UDP_SEND_GSO is set. On
 * Linux the sends of a batch go to the kernel together (sendmmsg),
 * elsewhere one sendmsg each. A datagram failing with a loss-like error is
 * dropped (counted in the status header); EAGAIN stops early. Returns the
 * number of records consumed (sent or dropped), or -errno for a
 * socket-level failure. */
JNIEXPORT jint JNICALL
Java_com_s_1exp_enso_quiche_Quiche_udpSendBatch(
        JNIEnv *env, jclass cls, jint fd, jlong slabAddr, jint slabCap, jlong metaAddr, jint metaCap,
        jint count, jint flags) {
    UNUSED(env); UNUSED(cls);
    if (fd < 0 || count < 0 || count > 4096) return SHIM_ERR_INVALID_ARGUMENT;
    uint8_t *meta = mem_range(metaAddr, metaCap, 0, (jlong)SEND_HEADER_LEN + (jlong)SEND_META_LEN * count);
    uint8_t *slab = mem_range(slabAddr, slabCap, 0, slabCap);
    if (meta == NULL || slab == NULL) return SHIM_ERR_INVALID_ARGUMENT;
    /* The status always describes this call, refused ones included. */
    put_i32(meta + SEND_STATUS_DROPPED, 0);
    put_i32(meta + SEND_STATUS_ERRNO, 0);
    put_i32(meta + SEND_STATUS_FLAGS, 0);
    /* Validate every record before sending anything. */
    for (int i = 0; i < count; i++) {
        const uint8_t *r = meta + SEND_HEADER_LEN + (size_t)i * SEND_META_LEN;
        int32_t off = get_i32(r + SEND_OFF), len = get_i32(r + SEND_LEN);
        if (off < 0 || len <= 0 || (jlong)off + len > slabCap) return SHIM_ERR_INVALID_ARGUMENT;
    }
    int32_t dropped = 0, lastErrno = 0, statusFlags = 0;
    int i = 0;
    struct msghdr msgs[MAX_BATCH];
    struct iovec iovs[MAX_BATCH];
    struct sockaddr_storage tos[MAX_BATCH];
    union { struct cmsghdr align; uint8_t buf[CMSG_BUF]; } cbufs[MAX_BATCH];
    int runs[MAX_BATCH];
#if defined(__linux__)
    const int group = MAX_BATCH;
#else
    const int group = 1;
#endif
    while (i < count) {
        /* The next sends, up to a group (sendmmsg on Linux); a record
         * without a destination address ends the group (it is dropped on
         * its own). */
        int m = 0, j = i;
        while (j < count && m < group) {
            const uint8_t *r = meta + SEND_HEADER_LEN + (size_t)j * SEND_META_LEN;
            socklen_t toLen = addr_get(r + SEND_TO, &tos[m]);
            if (toLen == 0) break;
            int segs = send_run(meta, j, count, flags);
            int32_t off = get_i32(r + SEND_OFF), len = get_i32(r + SEND_LEN);
            build_send(&msgs[m], &iovs[m], &tos[m], toLen, r + SEND_FROM, cbufs[m].buf, sizeof cbufs[m].buf,
                       slab + off, run_bytes(meta, j, segs), segs > 1 ? len : 0, flags);
            runs[m++] = segs;
            j += segs;
        }
        if (m == 0) {
            dropped++;
            i++;
            continue;
        }
        int sent;
#if defined(__linux__)
        struct mmsghdr mm[MAX_BATCH];
        for (int k = 0; k < m; k++) {
            mm[k].msg_hdr = msgs[k];
            mm[k].msg_len = 0;
        }
        do {
            sent = sendmmsg(fd, mm, (unsigned)m, 0);
        } while (sent < 0 && errno == EINTR);
#else
        ssize_t s;
        do {
            s = sendmsg(fd, &msgs[0], 0);
        } while (s < 0 && errno == EINTR);
        sent = s >= 0 ? 1 : -1;
#endif
        if (sent > 0) {
            for (int k = 0; k < sent; k++) i += runs[k];
            continue;
        }
        /* The first send of the group failed; it decides. */
        int e = errno;
        if (e == EAGAIN || e == EWOULDBLOCK) break;
        if (runs[0] > 1 && (e == EIO || e == EINVAL)) {
            /* The device can't segment: GSO off for good, resend singly. */
            flags &= ~UDP_SEND_GSO;
            statusFlags |= SEND_STATUS_GSO_DISABLED;
            continue;
        }
        if (send_error_is_loss(e)) {
            dropped += runs[0];
            lastErrno = e;
            i += runs[0];
            continue;
        }
        put_i32(meta + SEND_STATUS_DROPPED, dropped);
        put_i32(meta + SEND_STATUS_ERRNO, e);
        put_i32(meta + SEND_STATUS_FLAGS, statusFlags);
        return -e;
    }
    put_i32(meta + SEND_STATUS_DROPPED, dropped);
    put_i32(meta + SEND_STATUS_ERRNO, lastErrno);
    put_i32(meta + SEND_STATUS_FLAGS, statusFlags);
    return i;
}

/* True when the kernel accepts UDP_SEGMENT on fd. */
JNIEXPORT jboolean JNICALL
Java_com_s_1exp_enso_quiche_Quiche_udpGsoSupported(JNIEnv *env, jclass cls, jint fd) {
    UNUSED(env); UNUSED(cls);
#if defined(__linux__)
    int v = 0;
    socklen_t l = sizeof v;
    return getsockopt(fd, SOL_UDP, UDP_SEGMENT, &v, &l) == 0 ? JNI_TRUE : JNI_FALSE;
#else
    UNUSED(fd);
    return JNI_FALSE;
#endif
}

/* ------------------------------------------------------------------ */
/* Wake-ups and poll                                                    */
/* ------------------------------------------------------------------ */

/* A wake-up channel: (readFd << 32) | writeFd (one eventfd on Linux, a
 * pipe elsewhere), or -errno. */
JNIEXPORT jlong JNICALL
Java_com_s_1exp_enso_quiche_Quiche_wakeOpen(JNIEnv *env, jclass cls) {
    UNUSED(env); UNUSED(cls);
#if defined(__linux__)
    int fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (fd < 0) return -errno;
    return ((jlong)fd << 32) | (jlong)(uint32_t)fd;
#else
    int fds[2];
    if (pipe(fds) != 0) return -errno;
    if (set_nonblocking(fds[0]) != 0 || set_nonblocking(fds[1]) != 0) {
        int e = errno;
        close(fds[0]);
        close(fds[1]);
        return -e;
    }
    return ((jlong)fds[0] << 32) | (jlong)(uint32_t)fds[1];
#endif
}

JNIEXPORT void JNICALL
Java_com_s_1exp_enso_quiche_Quiche_wakeSignal(JNIEnv *env, jclass cls, jint writeFd) {
    UNUSED(env); UNUSED(cls);
    if (writeFd < 0) return;
#if defined(__linux__)
    uint64_t one = 1;
    ssize_t r;
    do { r = write(writeFd, &one, sizeof one); } while (r < 0 && errno == EINTR);
#else
    uint8_t one = 1;
    ssize_t r;
    do { r = write(writeFd, &one, 1); } while (r < 0 && errno == EINTR);
#endif
    (void)r; /* EAGAIN: a wake-up is already pending. */
}

JNIEXPORT void JNICALL
Java_com_s_1exp_enso_quiche_Quiche_wakeClose(JNIEnv *env, jclass cls, jlong handle) {
    UNUSED(env); UNUSED(cls);
    int rfd = (int)(handle >> 32), wfd = (int)(uint32_t)handle;
    if (rfd >= 0) close(rfd);
    if (wfd >= 0 && wfd != rfd) close(wfd);
}

/* One read clears the wake channel: an eventfd's counter resets whole; a
 * pipe holds at most a few bytes, since signals are coalesced while the
 * loop parks (a byte left behind only costs a spurious wake-up). */
static void drain_wake(int fd) {
    uint8_t buf[64];
    ssize_t r;
    do { r = read(fd, buf, sizeof buf); } while (r < 0 && errno == EINTR);
}

/* Waits until recvFd is readable, sendFd writable (when wantWrite), the
 * wake channel is signalled, or timeoutNanos pass (negative: no timeout).
 * Negative fds are ignored. A signalled wake channel is drained. Returns
 * POLL_* bits (0 on timeout or EINTR) or -errno. */
JNIEXPORT jint JNICALL
Java_com_s_1exp_enso_quiche_Quiche_poll(
        JNIEnv *env, jclass cls, jint recvFd, jint sendFd, jint wakeFd, jboolean wantWrite,
        jlong timeoutNanos) {
    UNUSED(env); UNUSED(cls);
    struct pollfd p[3];
    int n = 0, ri = -1, si = -1, wi = -1;
    if (recvFd >= 0) {
        p[n].fd = recvFd;
        p[n].events = POLLIN;
        if (wantWrite && sendFd == recvFd) p[n].events |= POLLOUT;
        p[n].revents = 0;
        ri = n++;
    }
    if (wantWrite && sendFd >= 0 && sendFd != recvFd) {
        p[n].fd = sendFd;
        p[n].events = POLLOUT;
        p[n].revents = 0;
        si = n++;
    }
    if (wakeFd >= 0) {
        p[n].fd = wakeFd;
        p[n].events = POLLIN;
        p[n].revents = 0;
        wi = n++;
    }
    int r;
#if defined(__linux__)
    struct timespec ts, *tsp = NULL;
    if (timeoutNanos >= 0) {
        ts.tv_sec = (time_t)(timeoutNanos / 1000000000LL);
        ts.tv_nsec = (long)(timeoutNanos % 1000000000LL);
        tsp = &ts;
    }
    r = ppoll(p, (nfds_t)n, tsp, NULL);
#else
    int ms = -1;
    if (timeoutNanos >= 0) {
        jlong m = (timeoutNanos + 999999LL) / 1000000LL;
        ms = m > 0x7fffffffLL ? 0x7fffffff : (int)m;
    }
    r = poll(p, (nfds_t)n, ms);
#endif
    if (r < 0) return errno == EINTR ? 0 : -errno;
    int bits = 0;
    if (ri >= 0) {
        if (p[ri].revents & (POLLIN | POLLERR | POLLHUP)) bits |= POLL_READABLE;
        if (p[ri].revents & POLLOUT) bits |= POLL_WRITABLE;
    }
    if (si >= 0 && (p[si].revents & (POLLOUT | POLLERR | POLLHUP))) bits |= POLL_WRITABLE;
    if (wi >= 0 && (p[wi].revents & (POLLIN | POLLERR | POLLHUP))) {
        bits |= POLL_WAKE;
        drain_wake(wakeFd);
    }
    return bits;
}

package com.s_exp.enso.http3;

/**
 * HTTP/3 SETTINGS identifiers we care about (RFC 9114 §7.2.4.1, RFC 9204
 * §5). Unknown settings are per spec silently ignored.
 */
public final class Http3SettingId {

    /** {@code SETTINGS_MAX_FIELD_SECTION_SIZE} — max uncompressed header list. */
    public static final long MAX_FIELD_SECTION_SIZE = 0x06;
    /** {@code SETTINGS_QPACK_MAX_TABLE_CAPACITY} — RFC 9204. */
    public static final long QPACK_MAX_TABLE_CAPACITY = 0x01;
    /** {@code SETTINGS_QPACK_BLOCKED_STREAMS} — RFC 9204. */
    public static final long QPACK_BLOCKED_STREAMS = 0x07;

    private Http3SettingId() {}
}

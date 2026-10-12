// ABOUTME: Isolates a private-key PEM block from a possibly multi-block file and wraps the common
// ABOUTME: unencrypted key encodings (PKCS8, PKCS1 RSA, SEC1 EC) into PKCS8 for the JDK KeyFactory.
package com.s_exp.enso.core;

import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reads a private key out of a PEM file and normalises it to PKCS8 so a
 * JDK {@code KeyFactory} can take it with no third-party library.
 *
 * <p>A file may carry several PEM blocks (an {@code EC PARAMETERS} block
 * before an {@code EC PRIVATE KEY} is the default {@code openssl ecparam
 * -genkey} output, and a key file may also hold the certificate). The
 * first block whose label names a private key is used; the rest are
 * ignored. Three unencrypted encodings are accepted:
 *
 * <ul>
 *   <li>{@code PRIVATE KEY} — PKCS8, taken as is.</li>
 *   <li>{@code RSA PRIVATE KEY} — PKCS1, wrapped in a PKCS8
 *       {@code PrivateKeyInfo} with the rsaEncryption algorithm.</li>
 *   <li>{@code EC PRIVATE KEY} — SEC1, wrapped in a PKCS8
 *       {@code PrivateKeyInfo} with the id-ecPublicKey algorithm and the
 *       named curve read out of the SEC1 structure.</li>
 * </ul>
 *
 * <p>The DER reader and writer here are the minimum the wrapping needs:
 * tag/length/value framing for one named-curve OID, and length encoding
 * for the PKCS8 envelope. They are deliberately small and strict so a
 * malformed key fails rather than producing a silently wrong one.
 */
final class Pem {

    private Pem() {}

    /** A private-key PEM block: its label and the base64-decoded DER. */
    record Block(String label, byte[] der) {}

    // The labels this reader can turn into a key; the PEM "type" in BEGIN/END.
    private static final String PKCS8 = "PRIVATE KEY";
    private static final String PKCS1_RSA = "RSA PRIVATE KEY";
    private static final String SEC1_EC = "EC PRIVATE KEY";
    private static final String ENCRYPTED = "ENCRYPTED PRIVATE KEY";

    // One PEM block: BEGIN <label> ... END <label>. The label repeats
    // (back-reference) so a block with mismatched markers never matches.
    private static final Pattern BLOCK = Pattern.compile(
        "-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \\1-----", Pattern.DOTALL);
    private static final Pattern WHITESPACE = Pattern.compile("\\s");

    // DER tags used by the reader and writer.
    private static final int INTEGER = 0x02;
    private static final int OCTET_STRING = 0x04;
    private static final int OBJECT_IDENTIFIER = 0x06;
    private static final int SEQUENCE = 0x30;
    // [0] EXPLICIT, the context-specific constructed tag that holds the
    // SEC1 curve parameters.
    private static final int EC_PARAMETERS = 0xA0;

    // AlgorithmIdentifier OIDs as whole DER TLVs (tag, length, value).
    // rsaEncryption, 1.2.840.113549.1.1.1.
    private static final byte[] RSA_OID = {
        0x06, 0x09, 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x01, 0x01};
    // id-ecPublicKey, 1.2.840.10045.2.1.
    private static final byte[] EC_OID = {
        0x06, 0x07, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x02, 0x01};
    // ASN.1 NULL, the parameters of an rsaEncryption AlgorithmIdentifier.
    private static final byte[] NULL = {0x05, 0x00};
    // PKCS8 PrivateKeyInfo version 0: INTEGER 0.
    private static final byte[] VERSION_0 = {0x02, 0x01, 0x00};

    /**
     * The first private-key block in {@code text}, base64 decoded. Throws
     * with an actionable message when the only key is encrypted, when no
     * private-key block is present, or when the base64 is corrupt.
     */
    static Block firstPrivateKey(String text, String path) throws IOException {
        boolean sawEncrypted = false;
        Matcher m = BLOCK.matcher(text);
        while (m.find()) {
            String label = m.group(1).trim();
            if (label.equals(PKCS8) || label.equals(PKCS1_RSA) || label.equals(SEC1_EC)) {
                return new Block(label, decode(m.group(2), path));
            }
            if (label.equals(ENCRYPTED)) {
                sawEncrypted = true;
            }
        }
        if (sawEncrypted) {
            throw new IOException("encrypted private key in " + path
                + " is not supported; convert it with: openssl pkcs8 -topk8 -nocrypt -in "
                + path + " -out key-pkcs8.pem");
        }
        throw new IOException("no PKCS8, PKCS1 or SEC1 private key block in " + path);
    }

    private static byte[] decode(String base64, String path) throws IOException {
        String clean = WHITESPACE.matcher(base64).replaceAll("");
        if (clean.isEmpty()) {
            throw new IOException("empty private key block in " + path);
        }
        try {
            return Base64.getDecoder().decode(clean);
        } catch (IllegalArgumentException e) {
            throw new IOException("private key is not valid base64 in " + path, e);
        }
    }

    /**
     * Wraps a PKCS1 {@code RSAPrivateKey} DER into a PKCS8
     * {@code PrivateKeyInfo}: {@code SEQUENCE { INTEGER 0,
     * AlgorithmIdentifier { rsaEncryption, NULL }, OCTET STRING <pkcs1> }}.
     */
    static byte[] pkcs8FromPkcs1Rsa(byte[] pkcs1) {
        byte[] algorithm = tlv(SEQUENCE, concat(RSA_OID, NULL));
        return tlv(SEQUENCE, concat(VERSION_0, algorithm, tlv(OCTET_STRING, pkcs1)));
    }

    /**
     * Wraps a SEC1 {@code ECPrivateKey} DER into a PKCS8
     * {@code PrivateKeyInfo}: {@code SEQUENCE { INTEGER 0,
     * AlgorithmIdentifier { id-ecPublicKey, <namedCurve> }, OCTET STRING
     * <sec1> }}. The named curve is read out of the SEC1 {@code [0]}
     * parameters; an explicit-parameter key (no curve OID) is rejected.
     */
    static byte[] pkcs8FromSec1Ec(byte[] sec1, String path) throws IOException {
        byte[] curve = namedCurveOid(sec1, path);
        byte[] algorithm = tlv(SEQUENCE, concat(EC_OID, curve));
        return tlv(SEQUENCE, concat(VERSION_0, algorithm, tlv(OCTET_STRING, sec1)));
    }

    /**
     * The named-curve OID, as a whole DER TLV, from a SEC1 key:
     * {@code ECPrivateKey ::= SEQUENCE { INTEGER 1, OCTET STRING
     * privateKey, [0] EXPLICIT parameters OPTIONAL, [1] EXPLICIT publicKey
     * OPTIONAL }}. The parameters are an {@code ECParameters} CHOICE whose
     * {@code namedCurve} arm is an OID; the explicit-curve arm (a SEQUENCE)
     * is not supported.
     */
    private static byte[] namedCurveOid(byte[] sec1, String path) throws IOException {
        Der top = new Der(sec1, 0, sec1.length);
        if (top.next() != SEQUENCE) {
            throw new IOException("EC private key in " + path + " is not a SEC1 SEQUENCE");
        }
        Der body = top.valueCursor();
        requireTag(body, INTEGER, path);        // version (1)
        requireTag(body, OCTET_STRING, path);   // the private scalar
        while (body.hasMore()) {
            if (body.next() == EC_PARAMETERS) {
                Der params = body.valueCursor();
                if (params.hasMore() && params.next() == OBJECT_IDENTIFIER) {
                    return tlv(OBJECT_IDENTIFIER, params.value());
                }
                throw new IOException("EC private key in " + path
                    + " uses explicit curve parameters, not a named curve; convert it with: openssl ec -in "
                    + path + " -param_enc named_curve -out key-named.pem");
            }
            // [1] publicKey or anything else: skip; next() already advanced.
        }
        throw new IOException("EC private key in " + path
            + " carries no named curve; convert it to a named-curve key with: openssl ec -in "
            + path + " -param_enc named_curve -out key-named.pem");
    }

    private static void requireTag(Der der, int tag, String path) throws IOException {
        if (!der.hasMore() || der.next() != tag) {
            throw new IOException("malformed SEC1 EC private key in " + path);
        }
    }

    // ---- Minimal DER writer ------------------------------------------------

    /** A DER TLV: the tag, the length (short or long form) and the value. */
    private static byte[] tlv(int tag, byte[] value) {
        byte[] length = derLength(value.length);
        byte[] out = new byte[1 + length.length + value.length];
        out[0] = (byte) tag;
        System.arraycopy(length, 0, out, 1, length.length);
        System.arraycopy(value, 0, out, 1 + length.length, value.length);
        return out;
    }

    /**
     * DER length: one byte under 128, else {@code 0x80 | byteCount}
     * followed by the length big-endian with no leading zero.
     */
    private static byte[] derLength(int length) {
        if (length < 0x80) {
            return new byte[] {(byte) length};
        }
        int bytes = 0;
        for (int v = length; v != 0; v >>>= 8) {
            bytes++;
        }
        byte[] out = new byte[1 + bytes];
        out[0] = (byte) (0x80 | bytes);
        for (int i = 0; i < bytes; i++) {
            out[bytes - i] = (byte) (length >>> (8 * i));
        }
        return out;
    }

    private static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] part : parts) {
            total += part.length;
        }
        byte[] out = new byte[total];
        int at = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, at, part.length);
            at += part.length;
        }
        return out;
    }

    // ---- Minimal DER reader ------------------------------------------------

    /**
     * A cursor over a DER buffer. {@link #next} reads one TLV, captures its
     * value range and advances past it; {@link #value} and {@link
     * #valueCursor} expose the value just read. Only the framing the SEC1
     * curve lookup needs is implemented, and every length is bounds checked.
     */
    private static final class Der {
        private final byte[] buffer;
        private int at;
        private final int end;
        private int valueStart;
        private int valueLength;

        Der(byte[] buffer, int at, int end) {
            this.buffer = buffer;
            this.at = at;
            this.end = end;
        }

        boolean hasMore() {
            return at < end;
        }

        /** Reads the next TLV, returns its tag, captures the value range. */
        int next() throws IOException {
            if (at >= end) {
                throw new IOException("truncated DER: expected a tag");
            }
            int tag = buffer[at++] & 0xff;
            int length = readLength();
            if (length > end - at) {
                throw new IOException("DER value overruns its container");
            }
            valueStart = at;
            valueLength = length;
            at += length;
            return tag;
        }

        private int readLength() throws IOException {
            if (at >= end) {
                throw new IOException("truncated DER: expected a length");
            }
            int first = buffer[at++] & 0xff;
            if (first < 0x80) {
                return first;
            }
            int count = first & 0x7f;
            if (count == 0 || count > 4) {
                throw new IOException("unsupported DER length form");
            }
            int length = 0;
            for (int i = 0; i < count; i++) {
                if (at >= end) {
                    throw new IOException("truncated DER length");
                }
                length = (length << 8) | (buffer[at++] & 0xff);
            }
            if (length < 0) {
                throw new IOException("DER length too large");
            }
            return length;
        }

        byte[] value() {
            return Arrays.copyOfRange(buffer, valueStart, valueStart + valueLength);
        }

        Der valueCursor() {
            return new Der(buffer, valueStart, valueStart + valueLength);
        }
    }
}

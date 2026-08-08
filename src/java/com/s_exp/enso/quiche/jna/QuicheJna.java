package com.s_exp.enso.quiche.jna;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.NativeLibrary;
import com.sun.jna.Pointer;

/**
 * JNA binding for the quiche functions we suspect trigger the JDK 25 FFM
 * heap-corruption crashes (task #79). Used as a surgical swap-in for the
 * FFM downcalls in the response-send path to test whether the JNI-layer
 * marshalling avoids the libmalloc freelist corruption.
 */
public interface QuicheJna extends Library {

    QuicheJna INSTANCE = loadFromKnownPrefixes();

    private static QuicheJna loadFromKnownPrefixes() {
        String[] prefixes = {
            System.getProperty("enso.quiche.path"),
            "/opt/homebrew/opt/cloudflare-quiche/lib",
            "/opt/homebrew/lib",
            "/usr/local/opt/cloudflare-quiche/lib",
            "/usr/local/lib",
            "/usr/lib",
            "/usr/lib/x86_64-linux-gnu",
            "/usr/lib/aarch64-linux-gnu",
        };
        for (String p : prefixes) {
            if (p == null) continue;
            NativeLibrary.addSearchPath("quiche", p);
        }
        return Native.load("quiche", QuicheJna.class);
    }

    long quiche_h3_send_body(Pointer h3conn, Pointer conn, long streamId,
                              byte[] body, long bodyLen, boolean fin);
}

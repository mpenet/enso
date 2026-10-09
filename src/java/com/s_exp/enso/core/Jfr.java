// ABOUTME: JDK Flight Recorder events for connections, requests and protocol errors, plus
// ABOUTME: static enabled flags so drivers pay one field read when no recording wants them.
package com.s_exp.enso.core;

import jdk.jfr.Category;
import jdk.jfr.Enabled;
import jdk.jfr.Event;
import jdk.jfr.EventType;
import jdk.jfr.FlightRecorder;
import jdk.jfr.FlightRecorderListener;
import jdk.jfr.Label;
import jdk.jfr.Name;
import jdk.jfr.Recording;
import jdk.jfr.StackTrace;

/**
 * Event classes and their enabled flags. A driver checks
 * {@link #requests()} (a static field read) before creating anything; an
 * event object is only allocated while a recording has that event
 * enabled. The flags follow recordings through a
 * {@link FlightRecorderListener}; on a runtime without the jdk.jfr module
 * they stay false.
 *
 * <p>Usage, request: {@code RequestEvent e = Jfr.requests() ? new RequestEvent() : null;
 * if (e != null) e.begin(); ... if (e != null) { set fields; e.commit(); }}.
 */
public final class Jfr {

    private static volatile boolean connections;
    private static volatile boolean requests;
    private static volatile boolean protocolErrors;

    static {
        try {
            FlightRecorder.addListener(new FlightRecorderListener() {
                @Override
                public void recordingStateChanged(Recording recording) {
                    refresh();
                }
            });
            refresh();
        } catch (Throwable ignored) {
            // No usable Flight Recorder: every flag stays false.
        }
    }

    private Jfr() {}

    private static void refresh() {
        connections = EventType.getEventType(ConnectionEvent.class).isEnabled();
        requests = EventType.getEventType(RequestEvent.class).isEnabled();
        protocolErrors = EventType.getEventType(ProtocolErrorEvent.class).isEnabled();
    }

    public static boolean connections() { return connections; }

    public static boolean requests() { return requests; }

    public static boolean protocolErrors() { return protocolErrors; }

    /** Records a protocol error when a recording wants it. */
    public static void protocolError(String protocol, String kind) {
        if (!protocolErrors) return;
        ProtocolErrorEvent e = new ProtocolErrorEvent();
        e.protocol = protocol;
        e.kind = kind;
        e.commit();
    }

    /** A connection's lifetime: begins once its protocol is known, commits at close. */
    @Name("com.s_exp.enso.Connection")
    @Label("Enso Connection")
    @Category({"Enso", "HTTP"})
    @StackTrace(false)
    public static final class ConnectionEvent extends Event {
        @Label("Protocol")
        public String protocol;
        @Label("Remote Address")
        public String remoteAddress;
    }

    /**
     * One request: from a complete head to the end of the response. Off
     * unless a recording enables it explicitly, like the JDK's own
     * high-frequency events: one event per request is too much for an
     * always-on recording.
     */
    @Name("com.s_exp.enso.Request")
    @Enabled(false)
    @Label("Enso Request")
    @Category({"Enso", "HTTP"})
    @StackTrace(false)
    public static final class RequestEvent extends Event {
        @Label("Protocol")
        public String protocol;
        @Label("Method")
        public String method;
        @Label("Status")
        public int status;
        @Label("Request Bytes")
        public long requestBytes;
        @Label("Response Bytes")
        public long bytes;
    }

    /** A peer broke the protocol (malformed request, flood, timeout). */
    @Name("com.s_exp.enso.ProtocolError")
    @Label("Enso Protocol Error")
    @Category({"Enso", "HTTP"})
    @StackTrace(false)
    public static final class ProtocolErrorEvent extends Event {
        @Label("Protocol")
        public String protocol;
        @Label("Kind")
        public String kind;
    }
}

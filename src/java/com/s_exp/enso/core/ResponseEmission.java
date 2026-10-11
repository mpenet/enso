// ABOUTME: The server-error mapping every multiplexed driver (HTTP/2, HTTP/3) applies before sending:
// ABOUTME: a WebSocket listener becomes 501, a response ResponseHead rejects becomes 500.
package com.s_exp.enso.core;

import com.s_exp.enso.api.Response;

/**
 * Turns a handler's {@link Response} into either a prepared
 * {@link ResponseHead} or the server-error status a multiplexed driver must
 * send in its place, so HTTP/2 and HTTP/3 share one error-mapping policy
 * instead of each re-deriving it. The byte-framing that follows stays with
 * the driver.
 */
public final class ResponseEmission {

    private ResponseEmission() {}

    /**
     * Prepares {@code head} from {@code response} in
     * {@link ResponseHead#MULTIPLEXED} mode, or returns the server-error
     * status to send in its place:
     * <ul>
     *   <li>501 for a WebSocket listener: neither HTTP/2 (RFC 9113 §8.6, no
     *       RFC 8441 Extended CONNECT) nor HTTP/3 (RFC 9114 §4.5) offers the
     *       101 / Upgrade a WebSocket needs;
     *   <li>500 for a response {@link ResponseHead#prepare} rejects (a
     *       handler error), logged through {@code invalidLog} (WARNING,
     *       rate-limited).
     * </ul>
     * The discarded response body is closed in either error case; 0 means
     * {@code head} is prepared and now owns the body.
     */
    public static int prepareMultiplexed(ResponseHead head, Response response, boolean headRequest,
                                         LogLimiter invalidLog) {
        if (response.webSocketListener != null) {
            Exchange.closeBody(response.body);
            return 501;
        }
        try {
            head.prepare(response, headRequest, ResponseHead.MULTIPLEXED);
            return 0;
        } catch (RuntimeException e) {
            invalidLog.log("invalid response from handler, sending 500", e);
            Exchange.closeBody(response.body);
            return 500;
        }
    }
}

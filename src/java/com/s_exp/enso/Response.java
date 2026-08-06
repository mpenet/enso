package com.s_exp.enso;

import java.util.Map;

public final class Response {

    public final int status;
    public final Map<?, ?> headers;
    public final Object body;
    public final WebSocketListener webSocketListener;
    public final String webSocketProtocol;

    public Response(int status, Map<?, ?> headers, Object body) {
        this(status, headers, body, null, null);
    }

    public Response(int status, Map<?, ?> headers, Object body,
                    WebSocketListener webSocketListener, String webSocketProtocol) {
        this.status = status;
        this.headers = headers;
        this.body = body;
        this.webSocketListener = webSocketListener;
        this.webSocketProtocol = webSocketProtocol;
    }
}

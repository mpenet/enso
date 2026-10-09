// ABOUTME: In-memory Socket for the connection fuzz targets: reads come from a fixed byte array,
// ABOUTME: writes go to a buffer, timeouts and shutdowns are recorded but never block.
package com.s_exp.enso.fuzz;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;

/**
 * A connected-looking socket whose peer sent {@code input} and then
 * half-closed: reads drain the array and then return EOF, so a
 * connection loop driven by it always terminates. An optional
 * {@code atEof} hook runs once, on the reading thread, before the first
 * EOF is returned (a harness waits there for work the input started).
 */
final class FakeSocket extends Socket {

    private final InputStream in;
    private final ByteArrayOutputStream out = new ByteArrayOutputStream();
    private boolean closed;
    private boolean outputShutdown;

    FakeSocket(byte[] input) {
        this(input, null);
    }

    FakeSocket(byte[] input, Runnable atEof) {
        this.in = atEof == null ? new ByteArrayInputStream(input) : new HookedInput(input, atEof);
    }

    byte[] written() {
        return out.toByteArray();
    }

    int writtenLength() {
        return out.size();
    }

    @Override
    public InputStream getInputStream() {
        return in;
    }

    @Override
    public OutputStream getOutputStream() {
        return out;
    }

    @Override
    public InetAddress getInetAddress() {
        return InetAddress.getLoopbackAddress();
    }

    @Override
    public SocketAddress getRemoteSocketAddress() {
        return new InetSocketAddress(InetAddress.getLoopbackAddress(), 40000);
    }

    @Override
    public SocketAddress getLocalSocketAddress() {
        return new InetSocketAddress(InetAddress.getLoopbackAddress(), 8080);
    }

    @Override
    public int getPort() {
        return 40000;
    }

    @Override
    public int getLocalPort() {
        return 8080;
    }

    @Override
    public void setSoTimeout(int timeout) {
    }

    @Override
    public void setSoLinger(boolean on, int linger) {
    }

    @Override
    public void setTcpNoDelay(boolean on) {
    }

    @Override
    public void shutdownOutput() {
        outputShutdown = true;
    }

    @Override
    public void shutdownInput() {
    }

    @Override
    public boolean isOutputShutdown() {
        return outputShutdown;
    }

    @Override
    public boolean isConnected() {
        return true;
    }

    @Override
    public boolean isClosed() {
        return closed;
    }

    @Override
    public synchronized void close() {
        closed = true;
    }

    private static final class HookedInput extends ByteArrayInputStream {
        private Runnable atEof;

        HookedInput(byte[] input, Runnable atEof) {
            super(input);
            this.atEof = atEof;
        }

        @Override
        public synchronized int read() {
            int b = super.read();
            if (b < 0) eof();
            return b;
        }

        @Override
        public synchronized int read(byte[] b, int off, int len) {
            int n = super.read(b, off, len);
            if (n < 0) eof();
            return n;
        }

        private void eof() {
            Runnable hook = atEof;
            atEof = null;
            if (hook != null) hook.run();
        }
    }
}

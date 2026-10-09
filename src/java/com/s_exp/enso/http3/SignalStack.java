// ABOUTME: Lock-free, allocation-free hand-off of signalled nodes (connections, exchanges) from any
// ABOUTME: thread to an event loop: intrusive Treiber stack drained whole and replayed oldest first.
package com.s_exp.enso.http3;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;

/**
 * Multi-producer, single-consumer. A node must be in at most one stack at
 * a time and pushed at most once until the consumer took it: producers
 * guard {@link #push} with a flag of their own (set by CAS before pushing,
 * cleared by the consumer when it handles the node). {@link #takeAll}
 * reads every link before returning, so a node handled (and its flag
 * cleared) can be pushed again at once without corrupting the batch
 * being walked.
 */
final class SignalStack<T extends SignalStack.Node<T>> {

    /** Intrusive links: one written by producers, one by the consumer. */
    interface Node<T> {
        T pushNext();

        void pushNext(T next);

        T takeNext();

        void takeNext(T next);
    }

    private static final VarHandle HEAD;

    static {
        try {
            HEAD = MethodHandles.lookup().findVarHandle(SignalStack.class, "head", Node.class);
        } catch (ReflectiveOperationException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    @SuppressWarnings("unused") // accessed through HEAD
    private volatile Node<T> head;

    @SuppressWarnings("unchecked")
    void push(T n) {
        Node<T> h;
        do {
            h = (Node<T>) HEAD.getVolatile(this);
            n.pushNext((T) h);
        } while (!HEAD.compareAndSet(this, h, n));
    }

    boolean isEmpty() {
        return HEAD.getVolatile(this) == null;
    }

    /**
     * Detaches everything pushed so far; returns it oldest first, chained
     * through {@link Node#takeNext} (null when empty).
     */
    @SuppressWarnings("unchecked")
    T takeAll() {
        T list = (T) HEAD.getAndSet(this, null);
        T out = null;
        while (list != null) {
            T next = list.pushNext();
            list.pushNext(null);
            list.takeNext(out);
            out = list;
            list = next;
        }
        return out;
    }
}

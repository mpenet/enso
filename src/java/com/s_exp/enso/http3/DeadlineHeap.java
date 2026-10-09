// ABOUTME: Binary min-heap of connections ordered by their next deadline, owned by one event loop:
// ABOUTME: O(log n) insert, update and removal through an index each node keeps, no allocation.
package com.s_exp.enso.http3;

import java.util.Arrays;

/**
 * The event loop's timers: each connection is in the heap at most once,
 * keyed by the earliest of its quiche timer, pacing release and
 * application deadlines. Single-threaded.
 */
final class DeadlineHeap<T extends DeadlineHeap.Node> {

    /** A heap entry: the node keeps its own deadline and position. */
    interface Node {
        /** System.nanoTime deadline. */
        long deadline();

        /** Position in the heap, -1 when absent. */
        int heapIndex();

        void heapIndex(int i);
    }

    private Node[] heap = new Node[64];
    private int size;

    int size() { return size; }

    @SuppressWarnings("unchecked")
    T peek() {
        return size == 0 ? null : (T) heap[0];
    }

    /** Inserts {@code n}, or restores its position after its deadline changed. */
    void update(T n) {
        int i = n.heapIndex();
        if (i < 0) {
            if (size == heap.length) heap = Arrays.copyOf(heap, size * 2);
            heap[size] = n;
            n.heapIndex(size);
            siftUp(size++);
        } else {
            siftUp(i);
            siftDown(n.heapIndex());
        }
    }

    void remove(T n) {
        int i = n.heapIndex();
        if (i < 0) return;
        n.heapIndex(-1);
        Node last = heap[--size];
        heap[size] = null;
        if (i == size) return;
        heap[i] = last;
        last.heapIndex(i);
        siftUp(i);
        siftDown(last.heapIndex());
    }

    @SuppressWarnings("unchecked")
    T poll() {
        if (size == 0) return null;
        T top = (T) heap[0];
        remove(top);
        return top;
    }

    private void siftUp(int i) {
        Node n = heap[i];
        long d = n.deadline();
        while (i > 0) {
            int parent = (i - 1) >>> 1;
            Node p = heap[parent];
            if (p.deadline() - d <= 0) break;
            heap[i] = p;
            p.heapIndex(i);
            i = parent;
        }
        heap[i] = n;
        n.heapIndex(i);
    }

    private void siftDown(int i) {
        Node n = heap[i];
        long d = n.deadline();
        int half = size >>> 1;
        while (i < half) {
            int child = 2 * i + 1;
            Node c = heap[child];
            int right = child + 1;
            if (right < size && heap[right].deadline() - c.deadline() < 0) {
                child = right;
                c = heap[child];
            }
            if (d - c.deadline() <= 0) break;
            heap[i] = c;
            c.heapIndex(i);
            i = child;
        }
        heap[i] = n;
        n.heapIndex(i);
    }
}

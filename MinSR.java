package my_test;

import it.unisa.dia.gas.jpbc.Element;

import java.util.*;

/**
 * Standalone MinSR implementation.
 *
 * This class follows the paper-level stateful syntax:
 *   st = (BT, S_reg, S_rev)
 * where BT stores LM and auxiliary flags.
 *
 * Notes for debugging:
 * 1. Node labels are sampled once in Initial() and never changed afterwards.
 * 2. Register() only updates LM / alive state.
 * 3. Revoke() follows the bottom-up disabling rule in the manuscript.
 */
public class MinSR {

    public static class Node {
        public final int index;          // heap-like index, root = 1
        public final int level;          // root = 1
        public final Element label;      // public node label g_v
        public Node left;
        public Node right;
        public Node parent;
        public boolean alive;
        public boolean disabled;

        public Node(int index, int level, Element label) {
            this.index = index;
            this.level = level;
            this.label = label.getImmutable();
            this.alive = false;
            this.disabled = false;
        }

        public boolean isLeaf() {
            return left == null && right == null;
        }

        @Override
        public String toString() {
            return "Node{" +
                    "index=" + index +
                    ", level=" + level +
                    ", alive=" + alive +
                    ", disabled=" + disabled +
                    '}';
        }
    }

    public static class State {
        public final int depth;
        public final Node root;
        public final List<Node> leaves;
        public final Map<String, Node> LM;           // partial leaf-assignment map
        public final Set<String> SReg;
        public final Set<String> SRev;
        private int nextUnassignedLeaf;

        public State(int depth, Node root, List<Node> leaves) {
            this.depth = depth;
            this.root = root;
            this.leaves = leaves;
            this.LM = new HashMap<>();
            this.SReg = new LinkedHashSet<>();
            this.SRev = new LinkedHashSet<>();
            this.nextUnassignedLeaf = 0;
        }

        public boolean isFull() {
            return SReg.size() >= leaves.size();
        }

        public Node getNextUnassignedLeaf() {
            while (nextUnassignedLeaf < leaves.size()) {
                Node candidate = leaves.get(nextUnassignedLeaf);
                if (!LM.containsValue(candidate)) {
                    nextUnassignedLeaf++;
                    return candidate;
                }
                nextUnassignedLeaf++;
            }
            for (Node candidate : leaves) {
                if (!LM.containsValue(candidate)) {
                    return candidate;
                }
            }
            return null;
        }
    }

    public static class RegisterResult {
        public final State state;
        public final Node leaf;
        public final boolean success;

        public RegisterResult(State state, Node leaf, boolean success) {
            this.state = state;
            this.leaf = leaf;
            this.success = success;
        }
    }

    public static class RevokeResult {
        public final State state;
        public final boolean changed;

        public RevokeResult(State state, boolean changed) {
            this.state = state;
            this.changed = changed;
        }
    }

    private final PP pp;

    public MinSR(PP pp) {
        this.pp = pp;
    }

    /** MinSR.Initial(d, G) -> state */
    public State initial(int depth) {
        if (depth < 1) {
            throw new IllegalArgumentException("depth must be >= 1");
        }
        List<Node> leaves = new ArrayList<>();
        Node root = buildFullBinaryTree(1, depth, null, leaves);
        return new State(depth, root, leaves);
    }

    private Node buildFullBinaryTree(int level, int depth, Node parent, List<Node> leaves) {
        int index;
        if (parent == null) {
            index = 1;
        } else {
            if (parent.left == null) {
                index = parent.index * 2;
            } else {
                index = parent.index * 2 + 1;
            }
        }

        Node node = new Node(index, level, pp.g_(pp.generateZr()));
        node.parent = parent;

        if (level < depth) {
            node.left = buildFullBinaryTree(level + 1, depth, node, leaves);
            node.right = buildFullBinaryTree(level + 1, depth, node, leaves);
        } else {
            leaves.add(node);
        }
        return node;
    }

    /** MinSR.Leaf(BT, id, S_reg) */
    public Node leaf(State st, String id) {
        if (!st.SReg.contains(id)) {
            return null;
        }
        return st.LM.get(id);
    }

    /** MinSR.Path(BT, id, S_reg) -> ordered list root -> leaf */
    public List<Node> path(State st, String id) {
        Node x = leaf(st, id);
        if (x == null) {
            return null;
        }
        List<Node> reversePath = new ArrayList<>();
        boolean found = subPathList(st.root, x, reversePath);
        if (!found) {
            return null;
        }
        Collections.reverse(reversePath);
        return reversePath;
    }

    private boolean subPathList(Node v, Node x, List<Node> acc) {
        if (v == null) {
            return false;
        }
        if (v == x) {
            acc.add(v);
            return true;
        }
        boolean foundL = subPathList(v.left, x, acc);
        if (foundL) {
            acc.add(v);
            return true;
        }
        boolean foundR = subPathList(v.right, x, acc);
        if (foundR) {
            acc.add(v);
            return true;
        }
        return false;
    }

    /** MinSR.Register(st, id) */
    public RegisterResult register(State st, String id) {
        if (st.LM.containsKey(id)) {
            return new RegisterResult(st, st.LM.get(id), true);
        }
        if (st.isFull()) {
            return new RegisterResult(st, null, false);
        }

        Node assigned = st.getNextUnassignedLeaf();
        if (assigned == null) {
            return new RegisterResult(st, null, false);
        }

        st.LM.put(id, assigned);
        st.SReg.add(id);

        List<Node> path = path(st, id);
        if (path == null) {
            throw new IllegalStateException("Path should exist right after registration for id=" + id);
        }
        for (Node node : path) {
            node.alive = true;
        }
        return new RegisterResult(st, assigned, true);
    }

    /** MinSR.Revoke(st, id) */
    public RevokeResult revoke(State st, String id) {
        if (!st.SReg.contains(id)) {
            return new RevokeResult(st, false);
        }
        if (st.SRev.contains(id)) {
            return new RevokeResult(st, false);
        }

        Node ell = leaf(st, id);
        if (ell == null) {
            throw new IllegalStateException("Registered id has no leaf: " + id);
        }

        // Update alive flags bottom-up
        ell.alive = false;
        Node v = ell;
        st.SRev.add(id);
        while (v != st.root) {
            Node p = v.parent;
            p.alive = (p.left != null && p.left.alive) || (p.right != null && p.right.alive);
            v = p;
        }

        // Bottom-up disabling rule
        ell.disabled = true;
        v = ell;
        while (v != st.root) {
            Node p = v.parent;
            Node s = sibling(v);
            if (isEmpty(s)) {
                p.disabled = true;
                v = p;
            } else {
                break;
            }
        }

        return new RevokeResult(st, true);
    }

    public boolean isEmpty(Node v) {
        return v == null || !v.alive;
    }

    public Node sibling(Node v) {
        if (v == null || v.parent == null) {
            return null;
        }
        return v.parent.left == v ? v.parent.right : v.parent.left;
    }

    public List<Element> getPathLabels(State st, String id) {
        List<Node> nodes = path(st, id);
        if (nodes == null) {
            return null;
        }
        List<Element> labels = new ArrayList<>();
        for (Node node : nodes) {
            labels.add(node.label.getImmutable());
        }
        return labels;
    }

    public void printTree(State st) {
        Queue<Node> q = new LinkedList<>();
        q.add(st.root);
        while (!q.isEmpty()) {
            int size = q.size();
            for (int i = 0; i < size; i++) {
                Node cur = q.poll();
                System.out.print("[idx=" + cur.index + ",lvl=" + cur.level + ",a=" + (cur.alive ? 1 : 0) + ",d=" + (cur.disabled ? 1 : 0) + "] ");
                if (cur.left != null) q.add(cur.left);
                if (cur.right != null) q.add(cur.right);
            }
            System.out.println();
        }
    }
}

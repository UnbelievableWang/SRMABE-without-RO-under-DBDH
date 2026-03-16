package my_test;

import it.unisa.dia.gas.jpbc.Element;

import java.math.BigInteger;
import java.util.*;

/**
 * Java framework implementation of the SR-MABE construction.
 *
 * Important honesty note:
 * - This file implements the scheme structure faithfully enough for debugging and code integration.
 * - The LSSS solving step (finding J and c_j such that sum c_j Gamma_j = (1,0,...,0))
 *   is implemented here only in a simplified "use all rows / assume coefficients provided or trivial" style.
 * - For full paper-grade experiments, you should replace solveReconstructionConstants()
 *   with exact linear algebra over Zr.
 */
public class SRMABE {

    private final PP pp;
    private final MinSR minSR;
    private final int depth;

    public SRMABE(PP pp, int depth) {
        this.pp = pp;
        this.minSR = new MinSR(pp);
        this.depth = depth;
    }

    // -------------------- Data classes --------------------

    public static class PublicParameters {
        public final PP pp;
        public final int depth;

        public PublicParameters(PP pp, int depth) {
            this.pp = pp;
            this.depth = depth;
        }
    }

    public static class AuthorityPK {
        public final Element eggAlpha;
        public final Map<Integer, Element> gY;   // k -> g^{y_k}, only for k = 2..d

        public AuthorityPK(Element eggAlpha, Map<Integer, Element> gY) {
            this.eggAlpha = eggAlpha.getImmutable();
            this.gY = gY;
        }
    }

    public static class AuthoritySK {
        public final Element alpha;
        public final Map<Integer, Element> y;     // k -> y_k, for 1..d

        public AuthoritySK(Element alpha, Map<Integer, Element> y) {
            this.alpha = alpha.getImmutable();
            this.y = y;
        }
    }

    public static class AuthorityState {
        public final String authorityId;
        public final AuthorityPK pk;
        public final AuthoritySK sk;
        public MinSR.State minsrState;
        public Element tau;

        public AuthorityState(String authorityId, AuthorityPK pk, AuthoritySK sk, MinSR.State minsrState, Element tau) {
            this.authorityId = authorityId;
            this.pk = pk;
            this.sk = sk;
            this.minsrState = minsrState;
            this.tau = tau.getImmutable();
        }
    }

    public static class UserKeyPair {
        public final String id;
        public final Element pkId;     // g^eta
        public final Element skId;     // eta in Zr
        public final Set<String> Iid;  // requested authority set

        public UserKeyPair(String id, Element pkId, Element skId, Set<String> iid) {
            this.id = id;
            this.pkId = pkId.getImmutable();
            this.skId = skId.getImmutable();
            this.Iid = iid;
        }
    }

    public static class URegResult {
        public final MinSR.State updatedState;
        public final List<Element> pi; // public path labels tuple

        public URegResult(MinSR.State updatedState, List<Element> pi) {
            this.updatedState = updatedState;
            this.pi = pi;
        }
    }

    public static class TransformInfo {
        public final Element Q1;
        public final Element Q2;

        public TransformInfo(Element q1, Element q2) {
            this.Q1 = q1.getImmutable();
            this.Q2 = q2.getImmutable();
        }
    }

    public static class TransformKey {
        public final Element K1;
        public final Element K2;

        public TransformKey(Element k1, Element k2) {
            this.K1 = k1.getImmutable();
            this.K2 = k2.getImmutable();
        }
    }

    public static class AccessPolicy {
        public final BigInteger[][] Gamma;  // l x d
        public final List<String> rho;      // size l, row j maps to authority rho[j]

        public AccessPolicy(BigInteger[][] gamma, List<String> rho) {
            this.Gamma = gamma;
            this.rho = rho;
        }

        public int rows() {
            return Gamma.length;
        }

        public int cols() {
            return Gamma[0].length;
        }
    }

    public static class CiphertextRow {
        public final Element C1;
        public final Element C2;
        public final Element C3;
        public final Map<Integer, Element> C4; // k -> C_{4,j,k}

        public CiphertextRow(Element c1, Element c2, Element c3, Map<Integer, Element> c4) {
            this.C1 = c1.getImmutable();
            this.C2 = c2.getImmutable();
            this.C3 = c3.getImmutable();
            this.C4 = c4;
        }
    }

    public static class Ciphertext {
        public final AccessPolicy policy;
        public final Map<String, Element> tauMap;
        public final Element C0;
        public final List<CiphertextRow> rows;

        public Ciphertext(AccessPolicy policy, Map<String, Element> tauMap, Element c0, List<CiphertextRow> rows) {
            this.policy = policy;
            this.tauMap = tauMap;
            this.C0 = c0.getImmutable();
            this.rows = rows;
        }
    }

    public static class TransformedCiphertext {
        public final Element CPrime;
        public final Element CDoublePrime;

        public TransformedCiphertext(Element cPrime, Element cDoublePrime) {
            this.CPrime = cPrime.getImmutable();
            this.CDoublePrime = cDoublePrime.getImmutable();
        }
    }

    public static class RevokeResult {
        public final AuthorityState authorityState;
        public final boolean revoked;

        public RevokeResult(AuthorityState authorityState, boolean revoked) {
            this.authorityState = authorityState;
            this.revoked = revoked;
        }
    }

    // -------------------- Setup --------------------

    public PublicParameters gSetup() {
        return new PublicParameters(pp, depth);
    }

    public AuthorityState aSetup(String authorityId) {
        Element alpha = pp.generateZr();
        Map<Integer, Element> y = new HashMap<>();
        for (int k = 1; k <= depth; k++) {
            y.put(k, pp.generateZr());
        }

        Element eggAlpha = pp.egg_(alpha).getImmutable();
        Map<Integer, Element> gY = new HashMap<>();
        for (int k = 2; k <= depth; k++) {
            gY.put(k, pp.g_(y.get(k)).getImmutable());
        }

        AuthorityPK pk = new AuthorityPK(eggAlpha, gY);
        AuthoritySK sk = new AuthoritySK(alpha, y);
        MinSR.State st = minSR.initial(depth);
        Element tau = pp.g_(pp.generateZr()).getImmutable();

        return new AuthorityState(authorityId, pk, sk, st, tau);
    }

    public UserKeyPair ukg(String id, Set<String> requestedAuthorities) {
        Element eta = pp.generateZr().getImmutable();
        Element pkId = pp.g_(eta).getImmutable();
        return new UserKeyPair(id, pkId, eta, new LinkedHashSet<>(requestedAuthorities));
    }

    // -------------------- MinSR wrappers --------------------

    public URegResult uReg(String id, AuthorityState authorityState) {
        MinSR.RegisterResult res = minSR.register(authorityState.minsrState, id);
        if (!res.success) {
            throw new IllegalStateException("UReg failed for id=" + id + " at authority=" + authorityState.authorityId);
        }
        authorityState.minsrState = res.state;
        List<Element> pi = minSR.getPathLabels(authorityState.minsrState, id);
        return new URegResult(authorityState.minsrState, pi);
    }

    // -------------------- Key generation --------------------

    /**
     * PAKG(id, pk_id, SK_i, {pi_u,id}_{u in I_id}, I_id)
     */
    public Element pakg(String id,
                        Element pkId,
                        AuthorityState authorityState,
                        Map<String, List<Element>> pathTuples,
                        Set<String> iid) {

        List<Element> selfPi = pathTuples.get(authorityState.authorityId);
        if (selfPi == null || selfPi.size() != depth) {
            throw new IllegalArgumentException("Missing own path tuple for authority " + authorityState.authorityId);
        }

        Element result = pp.g_(authorityState.sk.alpha).getImmutable();

        Element rootLabel = selfPi.get(0).getImmutable();
        result = result.mul(rootLabel.powZn(authorityState.sk.y.get(1))).getImmutable();

        for (int k = 2; k <= depth; k++) {
            Element prod = pp.G1.newOneElement().getImmutable();
            for (String u : iid) {
                List<Element> pi = pathTuples.get(u);
                if (pi == null || pi.size() < k) {
                    throw new IllegalArgumentException("Missing pi for authority=" + u + ", k=" + k);
                }
                prod = prod.mul(pi.get(k - 1)).getImmutable();
            }
            result = result.mul(prod.powZn(authorityState.sk.y.get(k))).getImmutable();
        }
        return result.getImmutable();
    }

    public TransformInfo transIG(String id, Element pkId, AuthorityState authorityState) {
        if (authorityState.minsrState.SRev.contains(id)) {
            return null;
        }

        List<Element> ownPi = minSR.getPathLabels(authorityState.minsrState, id);
        if (ownPi == null || ownPi.isEmpty()) {
            throw new IllegalStateException("User not registered at authority=" + authorityState.authorityId);
        }
        Element rootLabel = ownPi.get(0);

        Element t = pp.generateZr().getImmutable();
        Element gy1Root = rootLabel.powZn(authorityState.sk.y.get(1)).getImmutable();
        Element Q1 = authorityState.tau.powZn(t).div(gy1Root).getImmutable();
        Element Q2 = pkId.powZn(t).getImmutable();
        return new TransformInfo(Q1, Q2);
    }

    public TransformKey transKG(Element pkId, Element pakIdI, TransformInfo ti, Element tau) {
        if (ti == null) {
            return null;
        }
        Element tPrime = pp.generateZr().getImmutable();
        Element K1 = pakIdI.mul(ti.Q1).mul(tau.powZn(tPrime)).getImmutable();
        Element K2 = ti.Q2.mul(pkId.powZn(tPrime)).getImmutable();
        return new TransformKey(K1, K2);
    }

    // -------------------- Encryption --------------------

    public Ciphertext enc(Map<String, AuthorityState> authorities,
                          AccessPolicy policy,
                          Element messageGT,
                          Map<String, Element> tauMap) {

        Element s = pp.generateZr().getImmutable();

        Element[] v = new Element[depth + 1];
        Element[] w = new Element[depth + 1];
        v[1] = s;
        w[1] = pp.Zq.newZeroElement().getImmutable();
        for (int k = 2; k <= depth; k++) {
            v[k] = pp.generateZr().getImmutable();
            w[k] = pp.generateZr().getImmutable();
        }

        Element C0 = pp.egg_(s).mul(messageGT).getImmutable();
        List<CiphertextRow> rows = new ArrayList<>();

        for (int j = 0; j < policy.rows(); j++) {
            String auth = policy.rho.get(j);
            AuthorityState authority = authorities.get(auth);
            if (authority == null) {
                throw new IllegalArgumentException("Unknown authority in rho: " + auth);
            }

            Element rj = pp.generateZr().getImmutable();
            Element gammaDotV = dotProduct(policy.Gamma[j], v);
            Element C1 = pp.egg_(gammaDotV).mul(pp.egg_(authority.sk.alpha.mul(rj))).getImmutable();
            Element C2 = pp.g_(rj).getImmutable();
            Element C3 = tauMap.get(auth).powZn(rj).getImmutable();

            Map<Integer, Element> C4 = new HashMap<>();
            for (int k = 2; k <= depth; k++) {
                Element term1 = pp.g_(authority.sk.y.get(k).mul(rj)).getImmutable();
                Element gammaJK = pp.Zq.newElement(policy.Gamma[j][k - 1]).getImmutable();
                Element term2 = pp.g_(gammaJK.mul(w[k])).getImmutable();
                C4.put(k, term1.mul(term2).getImmutable());
            }
            rows.add(new CiphertextRow(C1, C2, C3, C4));
        }

        return new Ciphertext(policy, tauMap, C0, rows);
    }

    // -------------------- Transform / Decrypt --------------------

    public TransformedCiphertext transform(Element pkId,
                                           Ciphertext ct,
                                           Map<String, TransformKey> tkMap,
                                           Map<String, List<Element>> pathTuples,
                                           Set<String> iid) {

        List<Integer> candidateRows = new ArrayList<>();
        for (int j = 0; j < ct.policy.rows(); j++) {
            if (iid.contains(ct.policy.rho.get(j))) {
                candidateRows.add(j);
            }
        }
        if (candidateRows.isEmpty()) {
            throw new IllegalStateException("No usable rows in policy for given I_id");
        }

        ReconstructionResult rec = solveReconstructionConstants(ct.policy, candidateRows);
        if (rec == null) {
            throw new UnsupportedOperationException(
                    "Current debug implementation cannot reconstruct coefficients for this LSSS policy. " +
                    "Please replace solveReconstructionConstants() with exact linear algebra over Zr.");
        }

        Element denominator1 = pp.bp.getGT().newOneElement().getImmutable();
        Element denominator2 = pp.bp.getGT().newOneElement().getImmutable();

        for (Map.Entry<Integer, Element> entry : rec.coefficients.entrySet()) {
            int j = entry.getKey();
            Element cj = entry.getValue().getImmutable();
            String auth = ct.policy.rho.get(j);
            TransformKey tk = tkMap.get(auth);
            if (tk == null) {
                throw new IllegalArgumentException("Missing transform key for authority=" + auth);
            }

            CiphertextRow row = ct.rows.get(j);
            Element Tj = row.C1.mul(pp.e(row.C2, tk.K1).invert()).getImmutable();

            for (int k = 2; k <= depth; k++) {
                Element prodPi = pp.G1.newOneElement().getImmutable();
                for (String u : iid) {
                    List<Element> pi = pathTuples.get(u);
                    if (pi == null || pi.size() < k) {
                        throw new IllegalArgumentException("Missing path tuple for u=" + u + ", k=" + k);
                    }
                    prodPi = prodPi.mul(pi.get(k - 1)).getImmutable();
                }
                Tj = Tj.mul(pp.e(row.C4.get(k), prodPi)).getImmutable();
            }

            denominator1 = denominator1.mul(Tj.powZn(cj)).getImmutable();
            denominator2 = denominator2.mul(pp.e(row.C3, tk.K2).powZn(cj)).getImmutable();
        }

        Element cPrime = ct.C0.div(denominator1).getImmutable();
        Element cDoublePrime = denominator2.getImmutable();
        return new TransformedCiphertext(cPrime, cDoublePrime);
    }

    public Element dec(TransformedCiphertext ctPrime, Element skId) {
        Element etaInv = skId.invert().getImmutable();
        return ctPrime.CPrime.mul(ctPrime.CDoublePrime.powZn(etaInv).invert()).getImmutable();
    }

    // -------------------- Revoke --------------------

    public RevokeResult revoke(String id, AuthorityState authorityState) {
        MinSR.RevokeResult r = minSR.revoke(authorityState.minsrState, id);
        authorityState.minsrState = r.state;
        authorityState.tau = pp.g_(pp.generateZr()).getImmutable();
        return new RevokeResult(authorityState, r.changed);
    }

    // -------------------- Helpers --------------------

    private Element dotProduct(BigInteger[] row, Element[] vec) {
        Element sum = pp.Zq.newZeroElement().getImmutable();
        for (int i = 0; i < row.length; i++) {
            Element coeff = pp.Zq.newElement(row[i]).getImmutable();
            sum = sum.add(coeff.mul(vec[i + 1])).getImmutable();
        }
        return sum.getImmutable();
    }

    private static class ReconstructionResult {
        Map<Integer, Element> coefficients = new LinkedHashMap<>();
    }

    /**
     * Debug-friendly temporary solver.
     *
     * Supports the simplest and most common debugging case:
     *   rows whose first column sums to 1 and all remaining columns are 0,
     * or a single row equal to (1,0,...,0).
     *
     * Replace this with a true Gaussian elimination over Zr for full use.
     */
    private ReconstructionResult solveReconstructionConstants(AccessPolicy policy, List<Integer> candidateRows) {
        // Case 1: direct row equals e1
        for (int j : candidateRows) {
            boolean ok = policy.Gamma[j][0].equals(BigInteger.ONE);
            for (int c = 1; c < policy.cols(); c++) {
                ok = ok && policy.Gamma[j][c].equals(BigInteger.ZERO);
            }
            if (ok) {
                ReconstructionResult rr = new ReconstructionResult();
                rr.coefficients.put(j, pp.Zq.newOneElement().getImmutable());
                return rr;
            }
        }

        // Case 2: naive sum of rows = e1
        boolean possible = true;
        BigInteger[] sum = new BigInteger[policy.cols()];
        Arrays.fill(sum, BigInteger.ZERO);
        for (int j : candidateRows) {
            for (int c = 0; c < policy.cols(); c++) {
                sum[c] = sum[c].add(policy.Gamma[j][c]);
            }
        }
        if (!sum[0].equals(BigInteger.ONE)) {
            possible = false;
        }
        for (int c = 1; c < policy.cols(); c++) {
            if (!sum[c].equals(BigInteger.ZERO)) {
                possible = false;
                break;
            }
        }
        if (possible) {
            ReconstructionResult rr = new ReconstructionResult();
            for (int j : candidateRows) {
                rr.coefficients.put(j, pp.Zq.newOneElement().getImmutable());
            }
            return rr;
        }
        return null;
    }
}

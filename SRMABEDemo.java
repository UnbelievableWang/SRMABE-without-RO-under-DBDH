package my_test;

import it.unisa.dia.gas.jpbc.Element;

import java.math.BigInteger;
import java.util.*;

/**
 * Minimal runnable-style demo for the framework.
 *
 * This demo focuses on:
 * 1. ASetup / UKG / UReg
 * 2. PAKG / TransIG / TransKG
 * 3. MinSR tree state changes before and after revoke
 *
 * For easier debugging, the example policy is a single-row policy Gamma = [1,0,...,0],
 * which matches the temporary reconstruction solver in SRMABE.
 */
public class SRMABEDemo {

    public static void main(String[] args) {
        PP pp = new PP(128, 512);
        int depth = 4;
        SRMABE srmabe = new SRMABE(pp, depth);

        // Setup one authority A
        SRMABE.AuthorityState authA = srmabe.aSetup("A");
        Map<String, SRMABE.AuthorityState> authorities = new LinkedHashMap<>();
        authorities.put("A", authA);

        // User setup
        Set<String> requested = new LinkedHashSet<>();
        requested.add("A");
        SRMABE.UserKeyPair user = srmabe.ukg("user1", requested);

        // User registration at authority A
        SRMABE.URegResult uregA = srmabe.uReg(user.id, authA);
        Map<String, List<Element>> pathTuples = new LinkedHashMap<>();
        pathTuples.put("A", uregA.pi);

        System.out.println("==== MinSR tree after registration ====");
        new MinSR(pp).printTree(authA.minsrState);

        // Generate public attribute key / transform key
        Element pakA = srmabe.pakg(user.id, user.pkId, authA, pathTuples, user.Iid);
        SRMABE.TransformInfo tiA = srmabe.transIG(user.id, user.pkId, authA);
        SRMABE.TransformKey tkA = srmabe.transKG(user.pkId, pakA, tiA, authA.tau);

        Map<String, SRMABE.TransformKey> tkMap = new LinkedHashMap<>();
        tkMap.put("A", tkA);

        // Simple access policy: one row [1,0,0,0] mapped to authority A
        BigInteger[][] gamma = new BigInteger[][]{
                {BigInteger.ONE, BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO}
        };
        List<String> rho = Collections.singletonList("A");
        SRMABE.AccessPolicy policy = new SRMABE.AccessPolicy(gamma, rho);

        Map<String, Element> tauMap = new LinkedHashMap<>();
        tauMap.put("A", authA.tau);

        Element message = pp.egg_(pp.generateZr()).getImmutable();
        SRMABE.Ciphertext ct = srmabe.enc(authorities, policy, message, tauMap);
        SRMABE.TransformedCiphertext ctPrime = srmabe.transform(user.pkId, ct, tkMap, pathTuples, user.Iid);
        Element recovered = srmabe.dec(ctPrime, user.skId);

        System.out.println("Original message equals recovered? " + message.isEqual(recovered));

        // Revoke and inspect state
        srmabe.revoke(user.id, authA);
        System.out.println("==== MinSR tree after revoke ====");
        new MinSR(pp).printTree(authA.minsrState);

        SRMABE.TransformInfo tiAfterRevoke = srmabe.transIG(user.id, user.pkId, authA);
        System.out.println("TransformInfo after revoke is null? " + (tiAfterRevoke == null));
    }
}

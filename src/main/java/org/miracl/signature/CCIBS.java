package org.miracl.signature;


import org.miracl.*;
import org.miracl.Utilities.HASH2;
import org.miracl.Utilities.Uti;

public class CCIBS {
    public static final int BFS = CONFIG_BIG.MODBYTES;
    public static final int BGS = CONFIG_BIG.MODBYTES;
    public static final int CCIBS_OK = 0;
    public static final int CCIBS_FAIL = -1;

    public static FP4[] G2_TAB;

    static int ceil(int a, int b) {
        return (((a) - 1) / (b) + 1);
    }

    static FP[] hash_to_field(int hash, int hlen, byte[] DST, byte[] M, int ctr) {
        BIG q = new BIG(ROM.Modulus);
        int nbq = q.nbits();
        int L = ceil(nbq + CONFIG_CURVE.AESKEY * 8, 8);
        FP[] u = new FP[ctr];
        byte[] fd = new byte[L];

        byte[] OKM = HMAC.XMD_Expand(hash, hlen, L * ctr, DST, M);
        for (int i = 0; i < ctr; i++) {
            for (int j = 0; j < L; j++)
                fd[j] = OKM[i * L + j];
            u[i] = new FP(DBIG.fromBytes(fd).ctmod(q, 8 * L - nbq));
        }

        return u;
    }

    /* hash a message to an ECP point, using SHA2, random oracle method */
    public static ECP bls_hash_to_point(byte[] M) {
        String dst = new String("CCIBS_SIG_BLS12381G1_XMD:SHA-256_SVDW_RO_NUL_");
        FP[] u = hash_to_field(HMAC.MC_SHA2, CONFIG_CURVE.HASH_TYPE, dst.getBytes(), M, 2);

        ECP P = ECP.map2point(u[0]);
        ECP P1 = ECP.map2point(u[1]);
        P.add(P1);
        P.cfp();
        P.affine();
        return P;
    }

    public static int init() {
        ECP2 G = ECP2.generator();
        if (G.is_infinity()) return CCIBS_FAIL;
        G2_TAB = PAIR.precomp(G);
        return CCIBS_OK;
    }

    /* generate key pair, master private key MSK, master public key MPK */
    public static int KeyPairGenerate(byte[] MSK, byte[] MPK) {
        ECP2 G = ECP2.generator();
        BIG s = Uti.getRandomBig();
        s.toBytes(MSK);
        G = PAIR.G2mul(G, s);
        G.toBytes(MPK, true);
        return CCIBS_OK;
    }

    /* Extract the signing private key SSK corresponding to the ID with the master private key*/
    public static void Extract(String ID, byte[] MSK, byte[] SSK) {
        ECP Qid = bls_hash_to_point(ID.getBytes());
        BIG msk = BIG.fromBytes(MSK);
        PAIR.G1mul(Qid, msk).toBytes(SSK, true);
    }

    /* Sign message M using private key SSK to produce signature SIG */
    public static int core_sign(byte[][] SIG, byte[] M, byte[] SSK, String ID) {
        BIG rnd = Uti.getRandomBig();
        ECP Qid = bls_hash_to_point(ID.getBytes());
        ECP U = PAIR.G1mul(Qid, rnd);
        U.toBytes(SIG[0], true);
        BIG h = HASH2.MxG_to_Zq(M, SIG[0]);
        ECP Ssk = ECP.fromBytes(SSK);
        ECP V = PAIR.G1mul(Ssk, rnd.plus(h));
        V.toBytes(SIG[1], true);
        return CCIBS_OK;
    }

    /* Verify signature given message M, the ID,the signature SIG, and the master public key MPK */

    public static int core_verify(byte[][] SIG, byte[] M, String ID, byte[] MPK) {
        ECP Qid = bls_hash_to_point(ID.getBytes());

        ECP U = ECP.fromBytes(SIG[0]);
        ECP V = ECP.fromBytes(SIG[1]);
        V.neg();
        ECP2 Mpk = ECP2.fromBytes(MPK);

        BIG h = HASH2.MxG_to_Zq(M, SIG[0]);

        U.add(PAIR.G1mul(Qid, h));
        FP12[] r = PAIR.initmp();
        PAIR.another_pc(r, G2_TAB, V);
        PAIR.another(r, Mpk, U);
        FP12 v = PAIR.miller(r);

        v = PAIR.fexp(v);
        if (v.isunity())
            return CCIBS_OK;
        return CCIBS_FAIL;
    }


    public static void main(String[] args) {
        int BGS = CCIBS.BGS;
        int BFS = CCIBS.BFS;
        int G1S = BFS + 1; /* Group 1 Size - compressed */
        int G2S = 2 * BFS + 1; /* Group 2 Size - compressed */

        byte[] MSK = new byte[BGS];
        byte[] MPK = new byte[G2S];
        byte[][] SIG = new byte[2][G1S];

        byte[] SSK = new byte[G1S];

        int res = init();

        res = KeyPairGenerate(MSK, MPK);
        String ID = Uti.getRandomString();

        Extract(ID,MSK,SSK);
        byte[] M = Uti.getRandomString().getBytes();
        core_sign(SIG,M,SSK,ID);
        System.out.println(core_verify(SIG, M, ID, MPK));
    }

}

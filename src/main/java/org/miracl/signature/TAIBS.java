package org.miracl.signature;


import org.miracl.*;
import org.miracl.Utilities.HASH2;
import org.miracl.Utilities.Uti;

import java.security.SecureRandom;
import java.util.Random;

public class TAIBS {
    public static final int BFS = CONFIG_BIG.MODBYTES;
    public static final int BGS = CONFIG_BIG.MODBYTES;
    public static final int TABLS_OK = 0;
    public static final int TABLS_FAIL = -1;

    public static FP4[] G2_TAB;
    public static BIG order;

    static int ceil(int a, int b) {
        return (((a) - 1) / (b) + 1);
    }

    public static int init() {
        ECP2 G = ECP2.generator();
        if (G.is_infinity()) return TABLS_FAIL;
        G2_TAB = PAIR.precomp(G);
        order = new BIG(ROM.CURVE_Order);
        return TABLS_OK;
    }

    /* generate key pair, private key sk, public key PK */
    public static int KeyPairGenerate(byte[] MSK1, byte[] MPK1, byte[] MSK2, byte[] MPK2, byte[] SSK, byte[] SPK) {

        BIG tsk1 = Uti.getRandomBig();
        BIG tsk2 = Uti.getRandomBig();
        BIG ssk = Uti.getRandomBig();
        tsk1.toBytes(MSK1);
        tsk2.toBytes(MSK2);
        ssk.toBytes(SSK);

        // SkToPk
        PAIR.G2mul(ECP2.generator(), tsk1).toBytes(MPK1, true);
        PAIR.G2mul(ECP2.generator(), tsk2).toBytes(MPK2, true);
        PAIR.G2mul(ECP2.generator(), ssk).toBytes(SPK, true);
        return TABLS_OK;
    }


    public static void AddressGenerate(String ID, byte[] SPK, byte[] ADDR1, byte[] ADDR2) {
        ECP Qid = HASH2.hash_to_G1(ID.getBytes());
        ECP2 spk = ECP2.fromBytes(SPK);

        //ADDR1=aP
        BIG rnd_a = Uti.getRandomBig();
        PAIR.G2mul(ECP2.generator(), rnd_a).toBytes(ADDR1, true);

        //rnd_b=H(e(aQid,SPK))
        FP12[] r = PAIR.initmp();
        PAIR.another(r, spk, PAIR.G1mul(Qid, rnd_a));
        FP12 ate = PAIR.miller(r);
        ate = PAIR.fexp(ate);

        //ADDR2=bQid
        BIG rnd_b = HASH2.Gt_to_Zq(ate);
        PAIR.G1mul(Qid, rnd_b).toBytes(ADDR2, true);
    }

    public static void ExtractT(String ID, byte[] MSK1, byte[] MSK2, byte[][] TID) {
        ECP Qid = HASH2.hash_to_G1(ID.getBytes());
        BIG msk1 = BIG.fromBytes(MSK1);
        BIG msk2 = BIG.fromBytes(MSK2);

        BIG tau = Uti.getRandomBig();

        BIG big = BIG.modmul(msk1, msk1, order);
        big = BIG.modadd(BIG.modmul(msk2, tau, order), big, order);

        //extract tid2 (t1t1+t2\tau)Qid
        PAIR.G1mul(Qid, big).toBytes(TID[0], true);

        //extract tid2 \tau Qid
        PAIR.G1mul(Qid, tau).toBytes(TID[1], true);

        //extract tid3 t Qid
        PAIR.G1mul(Qid, msk1).toBytes(TID[2], true);

    }

    public static void ExtractS(String ID, byte[] SSK, byte[] SID) {
        ECP Qid = HASH2.hash_to_G1(ID.getBytes());
        BIG ssk = BIG.fromBytes(SSK);
        //extract
        PAIR.G1mul(Qid, ssk).toBytes(SID, true);
    }

    public static int core_sign(byte[][] SIG, byte[] M, byte[] SID, byte[][] TID, byte[] ADDR1, String ID) {
        ECP Sid = ECP.fromBytes(SID);
        ECP Tid1 = ECP.fromBytes(TID[0]);
        ECP Tid2 = ECP.fromBytes(TID[1]);
        ECP Tid3 = ECP.fromBytes(TID[2]);

        //e(A,DS)=e(aP,cQid)
        FP12[] r = PAIR.initmp();
        PAIR.another(r, ECP2.fromBytes(ADDR1), Sid);
        FP12 ate = PAIR.miller(r);
        ate = PAIR.fexp(ate);
        BIG b = HASH2.Gt_to_Zq(ate);

        BIG rnd = Uti.getRandomBig();

        //compute U
        ECP U = PAIR.G1mul(HASH2.hash_to_G1(ID.getBytes()), rnd);
        U.toBytes(SIG[0], true);

        //compute W
        PAIR.G1mul(Tid1, rnd).toBytes(SIG[2], true);

        //compute X
        PAIR.G1mul(Tid2, rnd).toBytes(SIG[3], true);

        //compute Y
        PAIR.G1mul(Tid3, rnd).toBytes(SIG[4], true);

        //compute V
        BIG h = HASH2.MxG_to_Zq(M, SIG[0], SIG[2], SIG[3], SIG[4]);
        rnd.add(BIG.modmul(b, h, order));
        ECP V = PAIR.G1mul(Sid, rnd);
        V.toBytes(SIG[1], true);
        return TABLS_OK;
    }

    /* Verify signature given message M, the signature SIG, and the public key W */

    public static int core_verify(byte[][] SIG, byte[] M, byte[] ADDR2, byte[] MPK1, byte[] MPK2, byte[] SPK) {
        ECP U = ECP.fromBytes(SIG[0]);
        ECP V = ECP.fromBytes(SIG[1]);

        ECP Vkey = ECP.fromBytes(ADDR2);
        ECP2 Mpk1 = ECP2.fromBytes(MPK1);
        ECP2 Mpk2 = ECP2.fromBytes(MPK2);
        ECP2 Spk = ECP2.fromBytes(SPK);

        BIG h = HASH2.MxG_to_Zq(M, SIG[0], SIG[2], SIG[3], SIG[4]);
        ECP ecp = PAIR.G1mul(Vkey, h);
        ecp.add(U);
        //O=e(-V,P)e(U, SPK)
        V.neg();

        FP12[] r = PAIR.initmp();
        PAIR.another_pc(r, G2_TAB, V);
        PAIR.another(r, Spk, ecp);
        FP12 v = PAIR.miller(r);

        v = PAIR.fexp(v);
        if (v.isunity()) {
            ECP W = ECP.fromBytes(SIG[2]);
            ECP X = ECP.fromBytes(SIG[3]);
            ECP Y = ECP.fromBytes(SIG[4]);

            FP12 ate = PAIR.ate(Mpk2, X);
            ate.mul(PAIR.ate(Mpk1, Y));
            ate = PAIR.fexp(ate);
            if (ate.equals(PAIR.fexp(PAIR.ate(ECP2.generator(), W)))) {
                Y.neg();
                r = PAIR.initmp();
                PAIR.another_pc(r, G2_TAB, Y);
                PAIR.another(r, Mpk1, U);
                v = PAIR.miller(r);
                v = PAIR.fexp(v);
                if (v.isunity()) {
                    return TABLS_OK;
                } else {
                    return TABLS_FAIL;
                }
            } else {
                return TABLS_FAIL;
            }
        } else
            return TABLS_FAIL;
    }

    public static int batch_verify(byte[][][] SIG, byte[][] M, byte[][] ADDR2, byte[] MPK1, byte[] MPK2, byte[] SPK) {
        ECP2 Mpk1 = ECP2.fromBytes(MPK1);
        ECP2 Mpk2 = ECP2.fromBytes(MPK2);
        ECP2 Spk = ECP2.fromBytes(SPK);

        ECP U = new ECP();
        ECP H = new ECP();
        ECP V = new ECP();
        ECP W = new ECP();
        ECP X = new ECP();
        ECP Y = new ECP();

        SecureRandom secureRandom = new SecureRandom();
        BIG rnd;
        for (int i = 0; i < SIG.length; i++) {
            rnd = new BIG(secureRandom.nextInt(Integer.MAX_VALUE - 1) + 1);

            ECP u = ECP.fromBytes(SIG[i][0]);
            ECP v = ECP.fromBytes(SIG[i][1]);
            ECP w = ECP.fromBytes(SIG[i][2]);
            ECP x = ECP.fromBytes(SIG[i][3]);
            ECP y = ECP.fromBytes(SIG[i][4]);
            u = PAIR.G1mul(u, rnd);
            U.add(u);
            V.add(PAIR.G1mul(v, rnd));
            W.add(PAIR.G1mul(w, rnd));
            X.add(PAIR.G1mul(x, rnd));
            Y.add(PAIR.G1mul(y, rnd));

            ECP Vkey = ECP.fromBytes(ADDR2[i]);

            BIG h = HASH2.MxG_to_Zq(M[i], SIG[i][0], SIG[i][2], SIG[i][3], SIG[i][4]);
            H.add(PAIR.G1mul(Vkey, BIG.modmul(h, rnd, order)));
            H.add(u);
        }


        V.neg();

        FP12[] r = PAIR.initmp();
        PAIR.another_pc(r, G2_TAB, V);
        PAIR.another(r, Spk, H);// FP12 v = PAIR.ate2(ECP2.generator(), V, MPK, U);
        FP12 v = PAIR.miller(r);
        v = PAIR.fexp(v);
        if (v.isunity()) {
            FP12 ate = PAIR.ate(Mpk2, X);
            ate.mul(PAIR.ate(Mpk1, Y));
            ate = PAIR.fexp(ate);
            if (ate.equals(PAIR.fexp(PAIR.ate(ECP2.generator(), W)))) {
                Y.neg();
                r = PAIR.initmp();
                PAIR.another_pc(r, G2_TAB, Y);
                PAIR.another(r, Mpk1, U);
                v = PAIR.miller(r);
                v = PAIR.fexp(v);
                if (v.isunity()) {
                    return TABLS_OK;
                } else {
                    return TABLS_FAIL;
                }
            } else {
                return TABLS_FAIL;
            }
        } else
            return TABLS_FAIL;
    }

    public static void main(String[] args) {
        int BGS = TAIBS.BGS;
        int BFS = TAIBS.BFS;
        int G1S = BFS + 1; /* Group 1 Size - compressed */
        int G2S = 2 * BFS + 1; /* Group 2 Size - compressed */

        byte[] MSK1 = new byte[BGS];
        byte[] MPK1 = new byte[G2S];
        byte[] MSK2 = new byte[BGS];
        byte[] MPK2 = new byte[G2S];
        byte[] SSK = new byte[BGS];
        byte[] SPK = new byte[G2S];

        byte[][] TID = new byte[3][G1S];
        byte[] SID = new byte[G1S];

        byte[] ADDR1 = new byte[G2S];
        byte[] ADDR2 = new byte[G1S];

        byte[][] SIG = new byte[5][G1S];


        int res = init();

        res = KeyPairGenerate(MSK1, MPK1, MSK2, MPK2, SSK, SPK);
        String ID = Uti.getRandomString();

        ExtractT(ID, MSK1, MSK2, TID);
        ExtractS(ID, SSK, SID);

        AddressGenerate(ID, SPK, ADDR1, ADDR2);

        byte[] M = Uti.getRandomString().getBytes();
        core_sign(SIG, M, SID, TID, ADDR1, ID);
        System.out.println(core_verify(SIG, M, ADDR2, MPK1, MPK2, SPK));
    }
}

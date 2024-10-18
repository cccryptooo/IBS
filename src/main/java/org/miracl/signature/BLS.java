package org.miracl.signature;


import org.miracl.*;
import org.miracl.Utilities.Uti;

public class BLS {
    public static final int BFS = CONFIG_BIG.MODBYTES;
    public static final int BGS = CONFIG_BIG.MODBYTES;
    public static final int BLS_OK = 0;
    public static final int BLS_FAIL = -1;

    public static FP4[] G2_TAB;

    static int ceil(int a,int b) {
        return (((a)-1)/(b)+1);
    }

    static FP[] hash_to_field(int hash, int hlen, byte[] DST, byte[] M, int ctr) {
        BIG q = new BIG(ROM.Modulus);
        int nbq = q.nbits();
        int L = ceil(nbq+CONFIG_CURVE.AESKEY*8,8);
        FP [] u = new FP[ctr];
        byte[] fd=new byte[L];

        byte[] OKM=HMAC.XMD_Expand(hash,hlen,L*ctr,DST,M);
        for (int i=0;i<ctr;i++)
        {
            for (int j=0;j<L;j++)
                fd[j]=OKM[i*L+j];
            u[i]=new FP(DBIG.fromBytes(fd).ctmod(q,8*L-nbq));
        }
    
        return u;
    }    

    /* hash a message to an ECP point, using SHA2, random oracle method */
    public static ECP bls_hash_to_point(byte[] M) {
        String dst= new String("BLS_SIG_BLS12381G1_XMD:SHA-256_SVDW_RO_NUL_");
        FP[] u=hash_to_field(HMAC.MC_SHA2,CONFIG_CURVE.HASH_TYPE,dst.getBytes(),M,2);

        ECP P=ECP.map2point(u[0]);
        ECP P1=ECP.map2point(u[1]);
        P.add(P1);
        P.cfp();
        P.affine();
        return P;
    }

    public static int init() {
        ECP2 G = ECP2.generator();
        if (G.is_infinity()) return BLS_FAIL;
        G2_TAB = PAIR.precomp(G);
        return BLS_OK;
    }

    /* generate key pair, private key S, public key W */
    public static int KeyPairGenerate(byte[] S, byte[] W) {

        ECP2 G = ECP2.generator();
        BIG s = Uti.getRandomBig();
        s.toBytes(S);
        PAIR.G2mul(G, s).toBytes(W,true);
        return BLS_OK;
    }

    /* Sign message M using private key S to produce signature SIG */

    public static int core_sign(byte[] SIG, byte[] M, byte[] S) {
        ECP D = bls_hash_to_point(M);
        BIG s = BIG.fromBytes(S);
        D = PAIR.G1mul(D, s);
 //       D.affine();
        D.toBytes(SIG, true);
        return BLS_OK;
    }

    /* Verify signature given message M, the signature SIG, and the public key W */

    public static int core_verify(byte[] SIG, byte[] M, byte[] W) {
        ECP HM = bls_hash_to_point(M);

        ECP D = ECP.fromBytes(SIG);
        if (!PAIR.G1member(D)) return BLS_FAIL;
        D.neg();
        ECP2 PK = ECP2.fromBytes(W);
        if (!PAIR.G2member(PK)) return BLS_FAIL;
        FP12[] r = PAIR.initmp();
        PAIR.another_pc(r, G2_TAB, D);
        PAIR.another(r, PK, HM);
        FP12 v = PAIR.miller(r);
        v = PAIR.fexp(v);
        if (v.isunity())
            return BLS_OK;
        return BLS_FAIL;
    }
}

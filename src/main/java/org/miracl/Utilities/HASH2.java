package org.miracl.Utilities;


import org.miracl.*;

public class HASH2 {
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
    public static ECP hash_to_G1(byte[] M) {
        String dst = new String("Traceable anonymous identity-based signature");
        FP[] u = hash_to_field(HMAC.MC_SHA2, CONFIG_CURVE.HASH_TYPE, dst.getBytes(), M, 2);

        ECP P = ECP.map2point(u[0]);
        ECP P1 = ECP.map2point(u[1]);
        P.add(P1);
        P.cfp();
        P.affine();
        return P;
    }


    public static BIG Gt_to_Zq(FP12 M) {
        return Uti.getRandomBig(M.toString().getBytes());
    }

    public static BIG MxG_to_Zq(byte[]... arrays) {
        int totalLength = 0;
        for (byte[] array : arrays) {
            totalLength += array.length;
        }

        byte[] result = new byte[totalLength];

        int offset = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, offset, array.length);
            offset += array.length;
        }
        return Uti.getRandomBig(result);
    }
}

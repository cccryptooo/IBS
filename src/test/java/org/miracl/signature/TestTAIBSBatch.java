package org.miracl.signature;  //

import junit.framework.TestCase;
import org.miracl.Utilities.Uti;

public class TestTAIBSBatch extends TestCase //
{
    public static void testTAIBS() {

        int BGS = TAIBS.BGS;
        int BFS = TAIBS.BFS;
        int G1S = BFS + 1; /* Group 1 Size - compressed */
        int G2S = 2 * BFS + 1; /* Group 2 Size - compressed */
        int flag = 0;
        int convert = 1000000;
        int[] num = {30, 30, 3, 10, 17, 24, 31, 38, 45};
        TAIBS.init();
        {
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

            TAIBS.KeyPairGenerate(MSK1, MPK1, MSK2, MPK2, SSK, SPK);
            String ID = Uti.getRandomString();

            TAIBS.ExtractT(ID, MSK1, MSK2, TID);
            TAIBS.ExtractS(ID, SSK, SID);

            TAIBS.AddressGenerate(ID, SPK, ADDR1, ADDR2);

            byte[] M = Uti.getRandomString().getBytes();
            TAIBS.core_sign(SIG, M, SID, TID, ADDR1, ID);
            flag += TAIBS.core_verify(SIG, M, ADDR2, MPK1, MPK2, SPK);
            if (flag == 0)
                System.out.println("Signature is OK");
            else
                fail("Signature is *NOT* OK");
        }

        byte[] bMSK1 = new byte[BGS];
        byte[] bMPK1 = new byte[G2S];
        byte[] bMSK2 = new byte[BGS];
        byte[] bMPK2 = new byte[G2S];
        byte[] bSSK = new byte[BGS];
        byte[] bSPK = new byte[G2S];
        long l1, l2;
        TAIBS.KeyPairGenerate(bMSK1, bMPK1, bMSK2, bMPK2, bSSK, bSPK);

        for (int i = 0; i < num.length; i++) {
            byte[][][] TID = new byte[num[i]][3][G1S];
            byte[][] SID = new byte[num[i]][G1S];

            byte[][] ADDR1 = new byte[num[i]][G2S];
            byte[][] ADDR2 = new byte[num[i]][G1S];

            byte[][][] SIG = new byte[num[i]][5][G1S];
            byte[][] M = new byte[num[i]][];
            String[] ID = new String[num[i]];

            for (int j = 0; j < num[i]; j++) {
                M[j] = Uti.getRandomString().getBytes();
                ID[j] = Uti.getRandomString();
                TAIBS.ExtractT(ID[j], bMSK1, bMSK2, TID[j]);
                TAIBS.ExtractS(ID[j], bSSK, SID[j]);
                TAIBS.AddressGenerate(ID[j], bSPK, ADDR1[j], ADDR2[j]);
                TAIBS.core_sign(SIG[j], M[j], SID[j], TID[j], ADDR1[j], ID[j]);
            }

            l1 = System.nanoTime();
            for (int j = 0; j < num[i]; j++) {
                flag += TAIBS.core_verify(SIG[j], M[j], ADDR2[j], bMPK1, bMPK2, bSPK);
            }
            l2 = System.nanoTime();
            System.out.printf("%.2f ms \t %d\t TA-IBS: core_verify \n", (l2 - l1) * 1.0 / convert, num[i]);
            System.out.printf("%.2f ms \t %d\t TA-IBS: core_verify \n", (l2 - l1) * 1.0 / num[i] / convert, num[i]);

            l1 = System.nanoTime();
            flag += TAIBS.batch_verify(SIG, M, ADDR2, bMPK1, bMPK2, bSPK);
            l2 = System.nanoTime();
            System.out.printf("%.2f ms \t %d\t TA-IBS: batch_verify \n", (l2 - l1) * 1.0 / convert, num[i]);
            System.out.printf("%.2f ms \t %d\t TA-IBS: batch_verify \n", (l2 - l1) * 1.0 / num[i] / convert, num[i]);

            if (flag == 0)
                System.out.println("Signature is OK");
            else
                fail("Signature is *NOT* OK");
        }
    }
}

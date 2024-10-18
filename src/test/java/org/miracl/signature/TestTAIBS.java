package org.miracl.signature;  //

import junit.framework.TestCase;
import org.miracl.Utilities.Uti;

public class TestTAIBS extends TestCase //
{
    public static void testTAIBS() {

        int BGS = TAIBS.BGS;
        int BFS = TAIBS.BFS;
        int G1S = BFS + 1; /* Group 1 Size - compressed */
        int G2S = 2 * BFS + 1; /* Group 2 Size - compressed */
        int flag = 0;
        int num = 1000;
        int convert = 1000000;

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

        byte[][] MSK1 = new byte[num][BGS];
        byte[][] MPK1 = new byte[num][G2S];
        byte[][] MSK2 = new byte[num][BGS];
        byte[][] MPK2 = new byte[num][G2S];
        byte[][] SSK = new byte[num][BGS];
        byte[][] SPK = new byte[num][G2S];

        byte[][][] TID = new byte[num][3][G1S];
        byte[][] SID = new byte[num][G1S];

        byte[][] ADDR1 = new byte[num][G2S];
        byte[][] ADDR2 = new byte[num][G1S];

        byte[][][] SIG = new byte[num][5][G1S];
        byte[][] M = new byte[num][];
        String[] ID = new String[num];


        long l1, l2;
        for (int i = 0; i < num; i++) {
            M[i] = Uti.getRandomString().getBytes();
            ID[i] = Uti.getRandomString();
        }

        l1 = System.nanoTime();
        for (int i = 0; i < num; i++) {
            TAIBS.KeyPairGenerate(MSK1[i], MPK1[i], MSK2[i], MPK2[i], SSK[i], SPK[i]);
        }
        l2 = System.nanoTime();
        System.out.printf("%.2f ms \t TA-IBS: KeyPairGenerate \n", (l2 - l1) * 1.0 / num / convert);

        l1 = System.nanoTime();
        for (int i = 0; i < num; i++) {
            TAIBS.ExtractT(ID[i], MSK1[i], MSK2[i], TID[i]);
            TAIBS.ExtractS(ID[i], SSK[i], SID[i]);
        }
        l2 = System.nanoTime();
        System.out.printf("%.2f ms \t TA-IBS: Extract \n", (l2 - l1) * 1.0 / num / convert);

        l1 = System.nanoTime();
        for (int i = 0; i < num; i++) {
            TAIBS.AddressGenerate(ID[i], SPK[i], ADDR1[i], ADDR2[i]);
        }
        l2 = System.nanoTime();
        System.out.printf("%.2f ms \t TA-IBS: AddressGenerate \n", (l2 - l1) * 1.0 / num / convert);

        l1 = System.nanoTime();
        for (int i = 0; i < num; i++) {
            TAIBS.core_sign(SIG[i], M[i], SID[i], TID[i], ADDR1[i], ID[i]);
        }
        l2 = System.nanoTime();
        System.out.printf("%.2f ms \t TA-IBS: core_sign \n", (l2 - l1) * 1.0 / num / convert);

        l1 = System.nanoTime();
        for (int i = 0; i < num; i++) {
            flag += TAIBS.core_verify(SIG[i], M[i], ADDR2[i], MPK1[i], MPK2[i], SPK[i]);
        }
        l2 = System.nanoTime();
        System.out.printf("%.2f ms \t TA-IBS: core_verify \n", (l2 - l1) * 1.0 / num / convert);

        if (flag == 0)
            System.out.println("Signature is OK");
        else
            fail("Signature is *NOT* OK");


    }
}

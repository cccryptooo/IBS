package org.miracl.signature;  //

import junit.framework.TestCase;
import org.miracl.Utilities.Uti;

public class TestCCIBS extends TestCase //
{
    public static void testCCIBS() {

        int BGS = CCIBS.BGS;
        int BFS = CCIBS.BFS;
        int G1S = BFS + 1; /* Group 1 Size - compressed */
        int G2S = 2 * BFS + 1; /* Group 2 Size - compressed */
        int flag = 0;
        int num = 1000;
        int convert = 1000000;

        CCIBS.init();
        {
            byte[] MSK = new byte[BGS];
            byte[] MPK = new byte[G2S];
            byte[][] SIG = new byte[2][G1S];

            byte[] SSK = new byte[G1S];

            CCIBS.KeyPairGenerate(MSK, MPK);
            String ID = Uti.getRandomString();
            CCIBS.Extract(ID, MSK, SSK);
            byte[] M = Uti.getRandomString().getBytes();
            flag += CCIBS.core_sign(SIG, M, SSK, ID);
            flag += CCIBS.core_verify(SIG, M, ID, MPK);
            if (flag == 0)
                System.out.println("Signature is OK");
            else
                fail("Signature is *NOT* OK");
        }

        byte[][] MSK = new byte[num][BGS];
        byte[][] MPK = new byte[num][G2S];
        byte[][][] SIG = new byte[num][2][G1S];

        byte[][] SSK = new byte[num][G1S];
        byte[][] M = new byte[num][];
        String[] ID = new String[num];


        long l1, l2;
        for (int i = 0; i < num; i++) {
            M[i] = Uti.getRandomString().getBytes();
            ID[i] = Uti.getRandomString();
        }

        l1 = System.nanoTime();
        for (int i = 0; i < num; i++) {
            CCIBS.KeyPairGenerate(MSK[i], MPK[i]);
        }
        l2 = System.nanoTime();
        System.out.printf("%.2f ms \t CC-IBS: KeyPairGenerate \n", (l2 - l1) * 1.0 / num / convert);

        l1 = System.nanoTime();
        for (int i = 0; i < num; i++) {
            CCIBS.Extract(ID[i], MSK[i], SSK[i]);
        }
        l2 = System.nanoTime();
        System.out.printf("%.2f ms \t CC-IBS: Extract \n", (l2 - l1) * 1.0 / num / convert);

        l1 = System.nanoTime();
        for (int i = 0; i < num; i++) {
            flag +=CCIBS.core_sign(SIG[i], M[i], SSK[i], ID[i]);
        }
        l2 = System.nanoTime();
        System.out.printf("%.2f ms \t CC-IBS: core_sign \n", (l2 - l1) * 1.0 / num / convert);

        l1 = System.nanoTime();
        for (int i = 0; i < num; i++) {
            flag +=CCIBS.core_verify(SIG[i], M[i], ID[i], MPK[i]);
        }
        l2 = System.nanoTime();
        System.out.printf("%.2f ms \t CC-IBS: core_verify \n", (l2 - l1) * 1.0 / num / convert);

        if (flag == 0)
            System.out.println("Signature is OK");
        else
            fail("Signature is *NOT* OK");


    }
}

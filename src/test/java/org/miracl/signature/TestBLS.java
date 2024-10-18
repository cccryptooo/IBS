package org.miracl.signature;

import junit.framework.TestCase;
import org.miracl.Utilities.Uti;


public class TestBLS extends TestCase
{
    public static void testBLS() {

        int BGS = BLS.BGS;
        int BFS = BLS.BFS;
        int G1S = BFS + 1; /* Group 1 Size - compressed */
        int G2S = 2 * BFS + 1; /* Group 2 Size - compressed */
        int flag = 0;
        int num = 1000;
        int convert = 1000000;
        BLS.init();
        {
            byte[] S = new byte[BGS];
            byte[] W = new byte[G2S];
            byte[] SIG = new byte[G1S];

            String mess = new String("This is a test message");
            BLS.KeyPairGenerate(S, W);
            BLS.core_sign(SIG, mess.getBytes(), S);
            flag = BLS.core_verify(SIG, mess.getBytes(), W);

            if (flag == 0)
                System.out.println("Signature is OK");
            else
                fail("Signature is *NOT* OK");
        }


        byte[][] S = new byte[num][BGS];
        byte[][] W = new byte[num][G2S];
        byte[][] SIG = new byte[num][G1S];
        byte[][] M = new byte[num][];


        long l1, l2;
        for (int i = 0; i < num; i++) {
            M[i] = Uti.getRandomString().getBytes();
        }

        l1 = System.nanoTime();
        for (int i = 0; i < num; i++) {
            BLS.KeyPairGenerate(S[i], W[i]);
        }
        l2 = System.nanoTime();
        System.out.printf("%.2f ms \t BLS: KeyPairGenerate \n", (l2 - l1) * 1.0 / num / convert);

        l1 = System.nanoTime();
        for (int i = 0; i < num; i++) {
            BLS.core_sign(SIG[i], M[i], S[i]);
        }
        l2 = System.nanoTime();
        System.out.printf("%.2f ms \t BLS: core_sign \n", (l2 - l1) * 1.0 / num / convert);

        l1 = System.nanoTime();
        for (int i = 0; i < num; i++) {
            flag += BLS.core_verify(SIG[i], M[i], W[i]);
        }
        l2 = System.nanoTime();
        System.out.printf("%.2f ms \t BLS: core_verify \n", (l2 - l1) * 1.0 / num / convert);

        if (flag == 0)
            System.out.println("Signature is OK");
        else
            fail("Signature is *NOT* OK");


    }
}

package org.miracl;

import org.miracl.Utilities.Uti;

import java.security.SecureRandom;

public class test {
    public static void main(String[] args) {
        BIG a = Uti.getRandomBig();
        BIG b = Uti.getRandomBig();


        BIG big = BIG.modadd(a, b, new BIG(ROM.CURVE_Order));

        ECP B = PAIR.G1mul(ECP.generator(), big);

        ECP A = PAIR.G1mul(ECP.generator(), a);
        ECP2 AA = PAIR.G2mul(ECP2.generator(), a);

        FP12 ate1 = PAIR.ate(AA, ECP.generator());
        FP12 ate2 = PAIR.ate(ECP2.generator(), A);
        System.out.println(ate1);
        System.out.println(ate2);

        FP12 fexp1 = PAIR.fexp(ate1);
        System.out.println(fexp1);
        FP12 fexp2 = PAIR.fexp(ate2);
        System.out.println(fexp2);


        ECP2 BB = PAIR.G2mul(ECP2.generator(), b);
        FP12 ate3 = PAIR.ate(BB, ECP.generator());
        ate2.mul(ate3);


        ate2 = PAIR.fexp(ate2);
        System.out.println(ate2);
        FP12 fexp = PAIR.fexp(PAIR.ate(ECP2.generator(), B));
        System.out.println(fexp);

    }

    private static void printBinary(byte[] array) {
        int i;
        for (i = 0; i < array.length; i++) {
            System.out.printf("%02x", array[i]);
        }
        System.out.println();
    }
}

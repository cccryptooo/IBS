package org.miracl.Utilities;


import org.miracl.*;

import java.security.SecureRandom;
import java.util.Random;

public class Uti {
    static byte[] RAW = new byte[100];
    static int ceil(int a, int b) {
        return (((a) - 1) / (b) + 1);
    }

    public static String getRandomString() {
        String str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        Random random = new Random();
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < 32; i++) {
            sb.append(str.charAt(random.nextInt(62)));
        }
        return sb.toString();
    }

    public static BIG getRandomBig(byte[] M) {
        RAND rng = new RAND();
        rng.clean();
        rng.seed(M.length, M);
        return BIG.randomnum(new BIG(ROM.CURVE_Order), rng);
    }

    public static BIG getRandomBig() {
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(RAW);
        return getRandomBig(RAW);
    }
}

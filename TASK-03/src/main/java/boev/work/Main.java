package boev.work;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Random;

public class Main {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final String ALGO = "GOST28147/ECB/PKCS5Padding";
    private static final int BLOCK_SIZE = 8;   // 64 бит
    private static final int KEY_SIZE = 32; // байт


    public static void main(String[] args) {

        if(args.length != 1){
            System.out.println("Неправильный ввод");
            System.exit(1);
        }

        try(BufferedInputStream in = new BufferedInputStream(new FileInputStream(args[0]))){

           byte[] outBytes =  gostDaviesMeyerHash(in);

           StringBuilder stringBuilder = new StringBuilder();

           for (byte b : outBytes){
               stringBuilder.append(String.format("%02X", b));
           }
           System.out.println(stringBuilder.toString());

           checkAlgorithm();

        }catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    public static byte[] gostDaviesMeyerHash(BufferedInputStream in) throws Exception{
        Cipher cipher = Cipher.getInstance(ALGO, "BC");

        byte[] hash = new byte[BLOCK_SIZE];
        new SecureRandom().nextBytes(hash);

        int r;
        long bytes = 0;
        byte[] buffer = new byte[KEY_SIZE];

         while((r = in.read(buffer)) > 0){
             bytes+= r;
             byte[] block;

             if (r < KEY_SIZE) {
                 block = applyPKCS5(buffer, r);
             } else {
                 block = Arrays.copyOf(buffer, KEY_SIZE);
             }

             cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(block,"GOST28147"));
             byte[] e = cipher.doFinal(hash);


             for(int i = 0; i < BLOCK_SIZE; ++i){
                 hash[i] ^= e[i];
             }
         }
         return hash;

    }

    private static byte[] applyPKCS5(byte[] input, int len) {
        int pad = KEY_SIZE - len;
        byte[] out = new byte[KEY_SIZE];
        System.arraycopy(input, 0, out, 0, len);
        Arrays.fill(out, len, KEY_SIZE, (byte) pad);
        return out;
    }

    public static int countDifferentBits(byte[] a, byte[] b){
        if(a.length != b.length) throw new IllegalArgumentException("Длины массивов не совпадают");

        int count = 0;
        for(int i = 0 ; i < a.length; ++i){
            int xor = a[i] ^ b[i];
            count += Integer.bitCount(xor & 0xFF);
        }
        return count;

    }

    public static void checkAlgorithm() throws Exception {
        byte[] original = "Hello world!".getBytes();

        byte[] hash1 = gostDaviesMeyerHash(new BufferedInputStream(new ByteArrayInputStream(original)));

        byte[] modified = Arrays.copyOf(original, original.length);
        modified[0] ^= 0x01;

        byte[] hash2 = gostDaviesMeyerHash(new BufferedInputStream(new ByteArrayInputStream(modified)));

        int diffBits = countDifferentBits(hash1, hash2);

        System.out.println("Изменилось бит: " + diffBits + " из " + (hash1.length * 8));
        System.out.println("В процентах: " + (double)diffBits / ((double)hash1.length * 8) * 100D);
    }

}
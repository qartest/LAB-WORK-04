package boev.work;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;

import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;




public class Main {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    private static final String ALGORITHM = "GOST28147/CBC/PKCS5Padding";
    private static final int KEY_SIZE_BYTES = 32; // 256 бит
    private static final int IV_SIZE_BYTES = 8;   // 64 бита



    public static void main(String[] args) {
        if(args.length != 4){
            System.out.println("Неправильный ввод");
            System.exit(1);
        }

        boolean encrypt = args[0].equals("0");

        try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(args[1]));
             BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(args[2]));
             BufferedOutputStream keyOut = encrypt ? new BufferedOutputStream(new FileOutputStream(args[3])) : null;
             BufferedInputStream keyIn = !encrypt ? new BufferedInputStream(new FileInputStream(args[3])) : null) {

            byte[] key = new byte[KEY_SIZE_BYTES];
            byte[] iv = new byte[IV_SIZE_BYTES];

            if(encrypt){
                new SecureRandom().nextBytes(key);
                keyOut.write(key);
                new SecureRandom().nextBytes(iv);
                encryptFile(in, out, key, iv);
            }else{
                keyIn.read(key);
                in.read(iv);
                decryptFile(in, out, key,iv);
            }


        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    public static void encryptFile(BufferedInputStream in, BufferedOutputStream out, byte[] keyBytes, byte[] ivBytes) throws Exception {
        SecretKey key = new SecretKeySpec(keyBytes, "GOST28147");
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        Cipher cipher = Cipher.getInstance(ALGORITHM, "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

        out.write(ivBytes);

        byte[] buffer = new byte[4096];
        int r;
        while ((r = in.read(buffer)) != -1) {
            byte[] outBuffer = cipher.update(buffer, 0, r);
            if (outBuffer != null) out.write(outBuffer);
        }
        byte[] finalBytes = cipher.doFinal();
        if (finalBytes != null) out.write(finalBytes);

    }

    public static void decryptFile(BufferedInputStream in, BufferedOutputStream out, byte[] keyBytes, byte[] ivBytes) throws Exception {
        SecretKey key = new SecretKeySpec(keyBytes, "GOST28147");
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        Cipher cipher = Cipher.getInstance(ALGORITHM, "BC");
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);



        byte[] buffer = new byte[4096];
        int r;
        while ((r = in.read(buffer)) != -1) {
            byte[] outBuffer = cipher.update(buffer, 0, r);
            if (out != null) out.write(outBuffer);
        }
        byte[] finalBytes = cipher.doFinal();
        if (finalBytes != null) out.write(finalBytes);

    }



}
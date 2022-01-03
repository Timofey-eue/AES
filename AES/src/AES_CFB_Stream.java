import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class AES_CFB_Stream {
    private static final String key = "1234567812345678";
    private static final String initVector = "0123456701234567";
    private static final byte[] header = new byte[60];

    public static void main(String[] args) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, InvalidAlgorithmParameterException {
        String plainFilename = "image.bmp";
        String encryptedFilename = "encrypt.bmp";
        String decryptedFilename = "decrypt.bmp";

  //      String plainFilename = "file.txt";
  //      String encryptedFilename = "encrypt.txt";
  //      String decryptedFilename = "decrypt.txt";

        encryptFile(plainFilename, encryptedFilename);
        decryptFile(encryptedFilename, decryptedFilename);

        encryptImage(plainFilename, encryptedFilename);
        decryptImage(encryptedFilename, decryptedFilename);
        System.out.println("file used for encryption: " + plainFilename);
        System.out.println("created encrypted file  : " + encryptedFilename);
        System.out.println("created decrypted file  : " + decryptedFilename);
    }

    public static void encryptFile(String filenamePlain, String filenameEnc) throws IOException,
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
        IvParameterSpec iv = new IvParameterSpec(initVector.getBytes(StandardCharsets.UTF_8));
        SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
        try (FileInputStream fis = new FileInputStream(filenamePlain);
             BufferedInputStream in = new BufferedInputStream(fis);
             FileOutputStream out = new FileOutputStream(filenameEnc);
             BufferedOutputStream bos = new BufferedOutputStream(out)) {
            byte[] ibuf = new byte[1024];
            int len;
            while ((len = in.read(ibuf)) != -1) {
                byte[] obuf = cipher.update(ibuf, 0, len);
                if (obuf != null)
                    bos.write(obuf);
            }
            byte[] obuf = cipher.doFinal();
            if (obuf != null)
                bos.write(obuf);
        }
    }

    public static void decryptFile(String filenameEnc, String filenameDec) throws IOException,
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        try (FileInputStream in = new FileInputStream(filenameEnc);
             FileOutputStream out = new FileOutputStream(filenameDec)) {
            byte[] ibuf = new byte[1024];
            int len;
            Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes(StandardCharsets.UTF_8));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            while ((len = in.read(ibuf)) != -1) {
                byte[] obuf = cipher.update(ibuf, 0, len);
                if (obuf != null)
                    out.write(obuf);
            }
            byte[] obuf = cipher.doFinal();
            if (obuf != null)
                out.write(obuf);
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    public static void encryptImage(String filenamePlain, String filenameEnc) throws IOException,
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
        IvParameterSpec iv = new IvParameterSpec(initVector.getBytes(StandardCharsets.UTF_8));
        SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
        try (FileInputStream fis = new FileInputStream(filenamePlain);
             BufferedInputStream in = new BufferedInputStream(fis);
             FileOutputStream out = new FileOutputStream(filenameEnc);
             BufferedOutputStream bos = new BufferedOutputStream(out)) {
            byte[] ibuf = new byte[1024];
            in.read(header);
            int len;
            bos.write(header);
            while ((len = in.read(ibuf)) != -1) {
                byte[] obuf = cipher.update(ibuf, 0, len);
                if (obuf != null)
                    bos.write(obuf);
            }
            byte[] obuf = cipher.doFinal();
            if (obuf != null)
                bos.write(obuf);
        }
    }

    public static void decryptImage(String filenameEnc, String filenameDec) throws IOException,
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        try (FileInputStream in = new FileInputStream(filenameEnc);
             FileOutputStream out = new FileOutputStream(filenameDec)) {
            byte[] ibuf = new byte[1024];
            int len;
            in.read(header);
            Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes(StandardCharsets.UTF_8));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            out.write(header);
            while ((len = in.read(ibuf)) != -1) {
                byte[] obuf = cipher.update(ibuf, 0, len);
                if (obuf != null)
                    out.write(obuf);
            }
            byte[] obuf = cipher.doFinal();
            if (obuf != null)
                out.write(obuf);
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }
}
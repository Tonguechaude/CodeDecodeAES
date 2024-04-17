package org.example;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.File;

/*
public class CodeDecodeAES
{
    static Cipher cipher;

    public static void main(String [] args) throws Exception
    {

        if (args.length < 3)
        {
            System.err.println("Usage : java -jar CodeDecodeAES --e (encrypt) ou --d (decrypt)  fd0 fd1");
            System.exit(1);
        }

        String option = args[0];
        String inputFileName = args[1];
        String outputFileName = args[2];

        //génération de la clef AES de 256 bits
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey secretKey = keyGenerator.generateKey();

        //instanciation d'un objet chiffreur implémentant le chiffrement AES
        cipher = Cipher.getInstance("AES");


        File inputFile = new File(inputFileName);
        File outputFile = new File(outputFileName);

        if (option.equals("--e"))
        {
            encryptFile(inputFile, outputFile, secretKey);
            System.out.println("Bien encrypté avec succès !");
        }
        else if (option.equals("--d"))
        {
            decryptFile(inputFile, outputFile, secretKey);
            System.out.println("Bien decrypté avec succès !");
        }
        else
        {
            System.err.println("Usage : java -jar CodeDecodeAES --e (encrypt) ou --d (decrypt)  fd0 fd1");
            System.exit(1);
        }

    /*
        // origine

        String plainText = "AES Symetric Encryption Decryption";
        System.out.println("Avant cryptage : " + plainText);

        // chiffré
        String encryptedText = encrypt(plainText, secretKey);
        System.out.println( "après cryptage : "+ encryptedText);

        // déchiffré
        String decryptedText = decrypt(encryptedText, secretKey);
        System.out.println("après decryptage : " + decryptedText);

        System.out.println(plainText.equals(decryptedText));
    */

/*

    }


    public static String decrypt(String encryptedText, SecretKey secretkey) throws Exception
    {
        // Chargement du chiffré dans un tableau de byte
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] encryptedTextByte = decoder.decode(encryptedText);

        // initialisation du chiffreur en mode decrypt avec la clef passée en param de la fonction
        cipher.init(Cipher.DECRYPT_MODE, secretkey);

        // dechiffrement du tableau d'octet
        byte[] decryptedByte = cipher.doFinal(encryptedTextByte);

        // String possede un constructeur qui prend en argument un tableau de byte
        String decryptedText = new String(decryptedByte, "UTF-8");
        return decryptedText;
    }

    public static String encrypt(String decryptedText, SecretKey secretKey) throws Exception
    {
        // chargement dans un tableau d'octet
        byte[] decryptedTextByte = decryptedText.getBytes("UTF-8");

        //byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        //IvParameterSpec ivspec = new IvParameterSpec(iv);

        // initialisation du chiffreur en mode Encrypt avec la secretkey passée en parametre
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        // chiffrement du tableau d'octet
        byte[] encryptedByte = cipher.doFinal(decryptedTextByte);

        //chaine de caractere representant le chiffree
        Base64.Encoder encoder = Base64.getEncoder();
        String encryptedText = encoder.encodeToString(encryptedByte);
        return encryptedText;
    }

    public static void encryptFile(File inputFile, File outputFile, SecretKey secretKey) throws Exception
    {
        Path inputPath = inputFile.toPath();
        Path outputPath = outputFile.toPath();

        byte[] fileByte = Files.readAllBytes(inputPath);

        String encryptedFileContent = encrypt(new String(fileByte), secretKey);

        Files.write(outputPath, encryptedFileContent.getBytes("UTF-8"));

    }


    public static void decryptFile (File inputFile, File outputFile, SecretKey secretKey) throws Exception
    {
        Path inputPath = inputFile.toPath();
        Path outputPath = outputFile.toPath();

        byte[] fileByte = Files.readAllBytes(inputPath);

        String decryptedFileContent = decrypt(new String(fileByte), secretKey);

        Files.write(outputPath, decryptedFileContent.getBytes("UTF-8"));
    }


}
*/

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class CodeDecodeAES {
    static Cipher cipher;

    public static void main(String[] args) {
        if (args.length < 3) {
            System.err.println("Usage: java -jar CodeDecodeAES --e (encrypt) or --d (decrypt) input_file output_file");
            System.exit(1);
        }

        String option = args[0];
        String inputFileName = args[1];
        String outputFileName = args[2];

        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            SecretKey secretKey = keyGenerator.generateKey();
            cipher = Cipher.getInstance("AES");

            File inputFile = new File(inputFileName);
            File outputFile = new File(outputFileName);

            if (option.equals("--e")) {
                encryptFile(inputFile, outputFile, secretKey);
                System.out.println("Successfully encrypted!");
            } else if (option.equals("--d")) {
                decryptFile(inputFile, outputFile, secretKey);
                System.out.println("Successfully decrypted!");
            } else {
                System.err.println("Usage: java -jar CodeDecodeAES --e (encrypt) or --d (decrypt) input_file output_file");
                System.exit(1);
            }
        } catch (Exception e) {
            System.err.println("An error occurred: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    public static String decrypt(String encryptedText, SecretKey secretKey) throws Exception {
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] encryptedTextByte = decoder.decode(encryptedText);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedByte = cipher.doFinal(encryptedTextByte);
        return new String(decryptedByte);
    }

    public static String encrypt(String decryptedText, SecretKey secretKey) throws Exception {
        byte[] decryptedTextByte = decryptedText.getBytes();
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedByte = cipher.doFinal(decryptedTextByte);
        Base64.Encoder encoder = Base64.getEncoder();
        return encoder.encodeToString(encryptedByte);
    }

    public static void encryptFile(File inputFile, File outputFile, SecretKey secretKey) throws Exception {
        try (InputStream input = Files.newInputStream(inputFile.toPath());
             OutputStream output = Files.newOutputStream(outputFile.toPath())) {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] inputBytes = input.readAllBytes();
            byte[] encryptedBytes = cipher.doFinal(inputBytes);
            output.write(encryptedBytes);
        }
    }

    public static void decryptFile(File inputFile, File outputFile, SecretKey secretKey) throws Exception {
        try (InputStream input = Files.newInputStream(inputFile.toPath());
             OutputStream output = Files.newOutputStream(outputFile.toPath())) {
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] inputBytes = input.readAllBytes();
            byte[] decryptedBytes = cipher.doFinal(inputBytes);
            output.write(decryptedBytes);
        }
    }


}

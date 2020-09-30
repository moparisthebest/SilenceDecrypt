/**
 * Copyright (C) 2011 Whisper Systems
 * Copyright (C) 2013 Open Whisper Systems
 * <p>
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * <p>
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * <p>
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.smssecure.smssecure.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

/**
 * Helper class for generating and securely storing a MasterSecret.
 *
 * @author Moxie Marlinspike
 */

public class MasterSecretUtil {

    public static final String UNENCRYPTED_PASSPHRASE = "unencrypted";
    public static final String PREFERENCES_NAME = "SecureSMS-Preferences";

    private static final String ASYMMETRIC_LOCAL_PUBLIC_DJB = "asymmetric_master_secret_curve25519_public";
    private static final String ASYMMETRIC_LOCAL_PRIVATE_DJB = "asymmetric_master_secret_curve25519_private";

    static {
        //Since Java 9 we set the unlimited crypto policy in code, not by applying the JCE jars.
        Security.setProperty("crypto.policy", "unlimited");
        //verify that JCE is applied

        // init the BC security provider
        if (Security.getProvider("BC") == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 0);
        }
    }

    public static MasterSecret getMasterSecret(File xmlFile, String passphrase) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(xmlFile);
            return getMasterSecret(doc, passphrase);
        } catch (ParserConfigurationException | SAXException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static MasterSecret getMasterSecret(Document context, String passphrase) {
        try {
            byte[] encryptedAndMacdMasterSecret = retrieve(context, "master_secret");
            byte[] macSalt = retrieve(context, "mac_salt");
            int iterations = retrieve(context, "passphrase_iterations", 100);
            byte[] encryptedMasterSecret = verifyMac(macSalt, iterations, encryptedAndMacdMasterSecret, passphrase);
            byte[] encryptionSalt = retrieve(context, "encryption_salt");
            byte[] combinedSecrets = decryptWithPassphrase(encryptionSalt, iterations, encryptedMasterSecret, passphrase);
            byte[] encryptionSecret = split(combinedSecrets, 16, 20)[0];
            byte[] macSecret = split(combinedSecrets, 16, 20)[1];

            return new MasterSecret(new SecretKeySpec(encryptionSecret, "AES"),
                    new SecretKeySpec(macSecret, "HmacSHA1"));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[][] split(byte[] input, int firstLength, int secondLength) {
        byte[][] parts = new byte[2][];

        parts[0] = new byte[firstLength];
        System.arraycopy(input, 0, parts[0], 0, firstLength);

        parts[1] = new byte[secondLength];
        System.arraycopy(input, firstLength, parts[1], 0, secondLength);

        return parts;
    }

    private static byte[] retrieve(Document context, String key) throws IOException {
        final var children = context.getElementsByTagName("string");
        String encodedValue = "";
        for(int x = 0; x < children.getLength(); ++x) {
            final var child = children.item(x);
            if(child.getAttributes().getNamedItem("name").getNodeValue().equals(key)) {
                encodedValue = child.getTextContent();
                break;
            }
        }
        //System.out.println(key + ":wa: " + encodedValue);

        if (encodedValue.isEmpty()) return null;
        else return Base64.getDecoder().decode(encodedValue);
    }

    private static int retrieve(Document context, String key, int defaultValue) throws IOException {
        final var children = context.getElementsByTagName("int");
        String encodedValue = "";
        for(int x = 0; x < children.getLength(); ++x) {
            final var child = children.item(x);
            if(child.getAttributes().getNamedItem("name").getNodeValue().equals(key)) {
                encodedValue = child.getAttributes().getNamedItem("value").getNodeValue();
                break;
            }
        }
        //System.out.println(key + ":wa: " + encodedValue);

        if (encodedValue.isEmpty()) return defaultValue;
        else return Integer.parseInt(encodedValue);
    }

    private static byte[] generateEncryptionSecret() {
        try {
            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(128);

            SecretKey key = generator.generateKey();
            return key.getEncoded();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] generateMacSecret() {
        try {
            KeyGenerator generator = KeyGenerator.getInstance("HmacSHA1");
            return generator.generateKey().getEncoded();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] generateSalt() throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[16];
        random.nextBytes(salt);

        return salt;
    }

    private static int generateIterationCount(String passphrase, byte[] salt) {
        int TARGET_ITERATION_TIME = 1000;   //ms
        int MINIMUM_ITERATION_COUNT = 10000;  //default for low-end devices
        int BENCHMARK_ITERATION_COUNT = 100000; //baseline starting iteration count

        try {
            PBEKeySpec keyspec = new PBEKeySpec(passphrase.toCharArray(), salt, BENCHMARK_ITERATION_COUNT);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBEWITHSHA1AND128BITAES-CBC-BC");

            long startTime = System.currentTimeMillis();
            skf.generateSecret(keyspec);
            long finishTime = System.currentTimeMillis();

            int scaledIterationTarget = (int) (((double) BENCHMARK_ITERATION_COUNT / (double) (finishTime - startTime)) * TARGET_ITERATION_TIME);

            if (scaledIterationTarget < MINIMUM_ITERATION_COUNT) return MINIMUM_ITERATION_COUNT;
            else if (scaledIterationTarget > BENCHMARK_ITERATION_COUNT) return BENCHMARK_ITERATION_COUNT;
            else return scaledIterationTarget;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return MINIMUM_ITERATION_COUNT;
        }
    }

    private static SecretKey getKeyFromPassphrase(String passphrase, byte[] salt, int iterations)
            throws GeneralSecurityException {
        PBEKeySpec keyspec = new PBEKeySpec(passphrase.toCharArray(), salt, iterations);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBEWITHSHA1AND128BITAES-CBC-BC");
        return skf.generateSecret(keyspec);
    }

    private static Cipher getCipherFromPassphrase(String passphrase, byte[] salt, int iterations, int opMode)
            throws GeneralSecurityException {
        SecretKey key = getKeyFromPassphrase(passphrase, salt, iterations);
        Cipher cipher = Cipher.getInstance(key.getAlgorithm());
        cipher.init(opMode, key, new PBEParameterSpec(salt, iterations));

        return cipher;
    }

    private static byte[] decryptWithPassphrase(byte[] encryptionSalt, int iterations, byte[] data, String passphrase)
            throws GeneralSecurityException, IOException {
        Cipher cipher = getCipherFromPassphrase(passphrase, encryptionSalt, iterations, Cipher.DECRYPT_MODE);
        return cipher.doFinal(data);
    }

    private static Mac getMacForPassphrase(String passphrase, byte[] salt, int iterations)
            throws GeneralSecurityException {
        SecretKey key = getKeyFromPassphrase(passphrase, salt, iterations);
        byte[] pbkdf2 = key.getEncoded();
        SecretKeySpec hmacKey = new SecretKeySpec(pbkdf2, "HmacSHA1");
        Mac hmac = Mac.getInstance("HmacSHA1");
        hmac.init(hmacKey);

        return hmac;
    }

    private static byte[] verifyMac(byte[] macSalt, int iterations, byte[] encryptedAndMacdData, String passphrase) throws GeneralSecurityException, IOException {
        Mac hmac = getMacForPassphrase(passphrase, macSalt, iterations);

        byte[] encryptedData = new byte[encryptedAndMacdData.length - hmac.getMacLength()];
        System.arraycopy(encryptedAndMacdData, 0, encryptedData, 0, encryptedData.length);

        byte[] givenMac = new byte[hmac.getMacLength()];
        System.arraycopy(encryptedAndMacdData, encryptedAndMacdData.length - hmac.getMacLength(), givenMac, 0, givenMac.length);

        byte[] localMac = hmac.doFinal(encryptedData);

        if (Arrays.equals(givenMac, localMac)) return encryptedData;
        else throw new RuntimeException("MAC Error");
    }

    private static byte[] macWithPassphrase(byte[] macSalt, int iterations, byte[] data, String passphrase) throws GeneralSecurityException {
        Mac hmac = getMacForPassphrase(passphrase, macSalt, iterations);
        byte[] mac = hmac.doFinal(data);
        byte[] result = new byte[data.length + mac.length];

        System.arraycopy(data, 0, result, 0, data.length);
        System.arraycopy(mac, 0, result, data.length, mac.length);

        return result;
    }
}

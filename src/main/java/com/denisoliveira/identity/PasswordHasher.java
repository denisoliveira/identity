package com.denisoliveira.identity;


import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;


/// Implements the standard Identity password hashing.

public class PasswordHasher {

    /* =======================
     * HASHED PASSWORD FORMATS
     * =======================
     *
     * Version 2:
     * PBKDF2 with HMAC-SHA1, 128-bit salt, 256-bit subkey, 1000 iterations.
     * (See also: SDL crypto guidelines v5.1, Part III)
     * Format: { 0x00, salt, subkey }
     *
     * Version 3:
     * PBKDF2 with HMAC-SHA256, 128-bit salt, 256-bit subkey, 10000 iterations.
     * Format: { 0x01, prf (UInt32), iter count (UInt32), salt length (UInt32), salt, subkey }
     * (All UInt32s are stored big-endian.)
     */


    public static byte[] hashPasswordV2(String password, Random rng) throws NoSuchAlgorithmException, InvalidKeySpecException {

        final SecretKeyFactory pbkdf2Factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1"); // default for Rfc2898DeriveBytes
        final int pbkdf2IterCount = 1000; // default for Rfc2898DeriveBytes
        final int pbkdf2SubkeyBitsLength = 256; // 256 bits
        final int pbkdf2SubkeyBytesLength = 256 / 8; // 256 bits
        final int saltSize = 128 / 8; // 128 bits

        // Produce a version 2 (see comment above) text hash.
        byte[] salt = new byte[saltSize];
        rng.nextBytes(salt);

        PBEKeySpec pbkdf2Spec = new PBEKeySpec(password.toCharArray(), salt, pbkdf2IterCount, pbkdf2SubkeyBitsLength);
        Key pbkdf2Key = pbkdf2Factory.generateSecret(pbkdf2Spec);

        byte[] subkey = pbkdf2Key.getEncoded();

        byte[] outputBytes = new byte[1 + saltSize + pbkdf2SubkeyBytesLength];
        outputBytes[0] = 0x00; // format marker

        System.arraycopy(salt, 0, outputBytes, 1, saltSize);
        System.arraycopy(subkey, 0, outputBytes, 1 + saltSize, pbkdf2SubkeyBytesLength);

        return outputBytes;
    }

    public static byte[] hashPasswordV3(String password, Random rng) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return hashPasswordV3(
                password,
                rng,
                SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256"),
                rng.nextInt(10000) + 1,
                128 / 8,
                256);
    }

    private static byte[] hashPasswordV3(String password, Random rng, SecretKeyFactory pbkdf2Factory, int iterCount, int saltSize, int numBitsRequested) throws InvalidKeySpecException {
        // Produce a version 3 (see comment above) text hash.
        byte[] salt = new byte[saltSize];
        rng.nextBytes(salt);

        PBEKeySpec pbkdf2Spec = new PBEKeySpec(password.toCharArray(), salt, iterCount, numBitsRequested);
        Key pbkdf2Key = pbkdf2Factory.generateSecret(pbkdf2Spec);

        byte[] subkey = pbkdf2Key.getEncoded();

        byte[] outputBytes = new byte[13 + salt.length + subkey.length];
        outputBytes[0] = 0x01; // format marker

        writeNetworkByteOrder(outputBytes, 1, (long) algorithmToId(pbkdf2Factory.getAlgorithm()));
        writeNetworkByteOrder(outputBytes, 5, (long) iterCount);
        writeNetworkByteOrder(outputBytes, 9, (long) saltSize);

        System.arraycopy(salt, 0, outputBytes, 13, salt.length);
        System.arraycopy(subkey, 0, outputBytes, 13 + saltSize, subkey.length);

        return outputBytes;
    }

    public static boolean verifyHashedPasswordV2(byte[] hashedPassword, String password) throws NoSuchAlgorithmException, InvalidKeySpecException {

        final SecretKeyFactory pbkdf2Factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1"); // default for Rfc2898DeriveBytes
        final int pbkdf2IterCount = 1000; // default for Rfc2898DeriveBytes
        final int pbkdf2SubkeyBitsLength = 256; // 256 bits
        final int pbkdf2SubkeyBytesLength = 256 / 8; // 256 bits
        final int saltSize = 128 / 8; // 128 bits

        // We know ahead of time the exact length of a valid hashed password payload.
        if (hashedPassword.length != 1 + saltSize + pbkdf2SubkeyBytesLength) {
            return false; // bad size
        }

        byte[] salt = new byte[saltSize];
        System.arraycopy(hashedPassword, 1, salt, 0, salt.length);

        byte[] expectedSubkey = new byte[pbkdf2SubkeyBytesLength];
        System.arraycopy(hashedPassword, 1 + salt.length, expectedSubkey, 0, expectedSubkey.length);

        // Hash the incoming password and verify it
        PBEKeySpec pbkdf2Spec = new PBEKeySpec(password.toCharArray(), salt, pbkdf2IterCount, pbkdf2SubkeyBitsLength);
        Key pbkdf2Key = pbkdf2Factory.generateSecret(pbkdf2Spec);
        byte[] actualSubkey = pbkdf2Key.getEncoded();

        return Arrays.equals(actualSubkey, expectedSubkey);
    }

    public static boolean verifyHashedPasswordV3(byte[] hashedPassword, String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Read header information
        SecretKeyFactory pbkdf2Factory = SecretKeyFactory.getInstance(idToAlgorithm(readNetworkByteOrder(hashedPassword, 1)));
        int iterCount = (int) readNetworkByteOrder(hashedPassword, 5);
        int saltLength = (int) readNetworkByteOrder(hashedPassword, 9);

        // Read the salt: must be >= 128 bits
        if (saltLength < 128 / 8) {
            return false;
        }
        byte[] salt = new byte[saltLength];
        System.arraycopy(hashedPassword, 13, salt, 0, salt.length);

        // Read the subkey (the rest of the payload): must be >= 128 bits
        int subkeyLength = hashedPassword.length - 13 - salt.length;
        if (subkeyLength < 128 / 8) {
            return false;
        }
        byte[] expectedSubkey = new byte[subkeyLength];
        System.arraycopy(hashedPassword, 13 + salt.length, expectedSubkey, 0, expectedSubkey.length);

        // Hash the incoming password and verify it
        PBEKeySpec pbkdf2Spec = new PBEKeySpec(password.toCharArray(), salt, iterCount, expectedSubkey.length * 8);
        Key pbkdf2Key = pbkdf2Factory.generateSecret(pbkdf2Spec);
        byte[] actualSubkey = pbkdf2Key.getEncoded();

        return Arrays.equals(actualSubkey, expectedSubkey);
    }


    public static boolean verifyHashedPassword(String hashedPassword, String providedPassword) throws InvalidKeySpecException, NoSuchAlgorithmException {

        if (hashedPassword == null || providedPassword == null) {
            return false;
        }

        // read the format marker from the hashed password
        byte[] decodedHashedPassword = Base64.getDecoder().decode(hashedPassword);

        if (decodedHashedPassword.length == 0) {
            return false;
        }

        switch (decodedHashedPassword[0]) {
            case 0x00:
                return verifyHashedPasswordV2(decodedHashedPassword, providedPassword);
            case 0x01:
                return verifyHashedPasswordV3(decodedHashedPassword, providedPassword);
            default:
                return false; // unknown format marker
        }
    }

    private static int algorithmToId(String algorithmName) {
        if (algorithmName.equals("PBKDF2WithHmacSHA1")) return 0;
        if (algorithmName.equals("PBKDF2WithHmacSHA256")) return 1;
        if (algorithmName.equals("PBKDF2WithHmacSHA512")) return 2;
        else return -1;
    }

    private static String idToAlgorithm(long algorithmId) {
        if (algorithmId == 0) return "PBKDF2WithHmacSHA1";
        if (algorithmId == 1) return "PBKDF2WithHmacSHA256";
        if (algorithmId == 2) return "PBKDF2WithHmacSHA512";
        else return null;
    }

    private static void writeNetworkByteOrder(byte[] buffer, int offset, long value) {
        buffer[offset] = (byte) (value >> 24);
        buffer[offset + 1] = (byte) (value >> 16);
        buffer[offset + 2] = (byte) (value >> 8);
        buffer[offset + 3] = (byte) (value);
    }

    private static long readNetworkByteOrder(byte[] buffer, int offset) {
        return ((long) (buffer[offset]) << 24)
                | ((long) (buffer[offset + 1]) << 16)
                | ((long) (buffer[offset + 2]) << 8)
                | ((long) (buffer[offset + 3]));
    }
}

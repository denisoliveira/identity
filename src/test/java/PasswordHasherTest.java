import com.denisoliveira.identity.PasswordHasher;
import org.junit.Assert;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Random;

public class PasswordHasherTest {

    @Test
    public void verifyHashedPassword() throws InvalidKeySpecException, NoSuchAlgorithmException {
        String hashedPassword = "AGC0ILs4UdnUesuTPb5wOZszOBSzXX8Zjj8wWPuwTdwVtJRLVyIXilel3Y3ukigykA==";
        Assert.assertTrue(PasswordHasher.verifyHashedPassword(hashedPassword, "password"));

        hashedPassword = "AQAAAAEAAAVRAAAAEDhR2dR6y5M9vnA5m/bJLaNilc8gNOCF3OiSevvI93zJHKPD5tm+CdZ5ZEUqLR/XlA==";
        Assert.assertTrue(PasswordHasher.verifyHashedPassword(hashedPassword, "password"));
    }

    @Test
    public void hashPasswordV2() throws InvalidKeySpecException, NoSuchAlgorithmException {
        String hashedPassword = new String(Base64.getEncoder().encode(PasswordHasher.hashPasswordV2("password", new Random(0))));
        Assert.assertNotNull("Invalid hash", hashedPassword);
    }

    @Test
    public void hashPasswordV3() throws InvalidKeySpecException, NoSuchAlgorithmException {
        String hashedPassword = new String(Base64.getEncoder().encode(PasswordHasher.hashPasswordV3("password", new Random(0))));
        Assert.assertNotNull("Invalid hash", hashedPassword);
    }

    @Test
    public void hashPasswordV2Math() throws InvalidKeySpecException, NoSuchAlgorithmException {
        String hashedPassword = new String(Base64.getEncoder().encode(PasswordHasher.hashPasswordV2("password", new Random(0))));
        Assert.assertEquals("AGC0ILs4UdnUesuTPb5wOZszOBSzXX8Zjj8wWPuwTdwVtJRLVyIXilel3Y3ukigykA==", hashedPassword);
    }

    @Test
    public void hashPasswordV3Math() throws InvalidKeySpecException, NoSuchAlgorithmException {
        String hashedPassword = new String(Base64.getEncoder().encode(PasswordHasher.hashPasswordV3("password", new Random(0))));
        Assert.assertEquals("AQAAAAEAAAVRAAAAEDhR2dR6y5M9vnA5m/bJLaNilc8gNOCF3OiSevvI93zJHKPD5tm+CdZ5ZEUqLR/XlA==", hashedPassword);
    }

    @Test
    public void verifyPasswordV2() throws InvalidKeySpecException, NoSuchAlgorithmException {
        byte[] bytes = Base64.getDecoder().decode("AGC0ILs4UdnUesuTPb5wOZszOBSzXX8Zjj8wWPuwTdwVtJRLVyIXilel3Y3ukigykA==");
        Assert.assertTrue(PasswordHasher.verifyHashedPasswordV2(bytes, "password"));
    }

    @Test
    public void verifyPasswordV3() throws InvalidKeySpecException, NoSuchAlgorithmException {
        byte[] bytes = Base64.getDecoder().decode("AQAAAAEAAAVRAAAAEDhR2dR6y5M9vnA5m/bJLaNilc8gNOCF3OiSevvI93zJHKPD5tm+CdZ5ZEUqLR/XlA==");
        Assert.assertTrue(PasswordHasher.verifyHashedPasswordV3(bytes, "password"));
    }
}
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package crypto.encryptor.util;

import crypto.encryptor.enums.HashFunctionEnum;
import static crypto.encryptor.util.EncryptorUtil.UTF8;
import java.io.UnsupportedEncodingException;
import java.util.List;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.ArrayList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.mindrot.jbcrypt.BCrypt;

/**
 *
 * @author Samuel Huang
 * Date: 13/04/2016
 */
public final class HashFunctionUtil {
    
    private static List<HashFunctionEnum> unsupportedHashFunctionList = new ArrayList<HashFunctionEnum>();
    
    // Define the BCrypt workload to use when generating password hashes. 10-31 is a valid value.
    private static final int BCRYPT_WORKLOAD = 12;


    // More hash functions will be added in future. Right now the only supported hash functions are
    // MD5, SHA-1, SHA-256, BCrypt
    
    /**
     * Hashing food for thoughts:
     * - http://howtodoinjava.com/security/how-to-generate-secure-password-hash-md5-sha-pbkdf2-bcrypt-examples/
     * - http://www.mindrot.org/projects/jBCrypt/
     * - https://www.owasp.org/index.php/Hashing_Java
     * - https://crackstation.net/hashing-security.htm
     * - https://www.cigital.com/blog/proper-use-of-javas-securerandom/
     */
    
    static {
        // Add unsupported hash functions in list here
        // unsupportedHashFunctionList.add( HashFunctionEnum.BCRYPT );
    }
    
    private static final Logger logger = LogManager.getLogger();
    
    /**
     * A static method for hashing data with a chosen hash function depending on input parameters.
     * 
     * @param salt             the salt value
     * @param data             the data to hash
     * @param hashFunctionEnum the enum representing hash function
     * @return                 the hashed data as Base64 encoded string
     */
    public static String hash(String salt, String data, HashFunctionEnum hashFunctionEnum) throws UnsupportedEncodingException {

        logger.debug( "Hashing data with key='" + salt + "', value='" + data + "', Hash function=" + hashFunctionEnum);
        
        if ( hashFunctionEnum == null ) {
            throw new IllegalArgumentException("Input argument 'hashFunctionEnum' of " + 
                "type HashFunctionEnum can't be null ");
        }
    
        if ( unsupportedHashFunctionList.contains( hashFunctionEnum ) ) {
            throw new UnsupportedOperationException( "The hash function " + hashFunctionEnum.value() 
                + " is not supported.");
        }

        String hashedString = null;
        if ( hashFunctionEnum == HashFunctionEnum.BCRYPT ) {
            
            hashedString = bCryptHashPassword( data, salt );
            
        } else {
            
            MessageDigest messageDigest = null;
            try {
                messageDigest = MessageDigest.getInstance( hashFunctionEnum.value() );
            } catch (Exception ex) {
                ex.printStackTrace(); 
                logger.error( "Error hashing data by Hash function '" + hashFunctionEnum.name() + "'", ex  );
                return null;
            }

            messageDigest.update(salt.getBytes());
            messageDigest.update(data.getBytes());
            byte[] hashedBytes = messageDigest.digest();
            
            // Use this if need to output byte as HEX encoded string. 
            //
            // The use of DatatypeConverter.printHexBinary(..) is gold, see 
            // https://stackoverflow.com/questions/9655181/how-to-convert-a-byte-array-to-a-hex-string-in-java for why.
            // return javax.xml.bind.DatatypeConverter.printHexBinary( bytesArray );
        
            hashedString = new String( Base64.encode( hashedBytes ), UTF8);
        }
        
        return hashedString;
    }
    
    /**
     * 
     * This method can be used to generate a string representing a hashed password
     * suitable for storing in a database. It will be an OpenBSD-style crypt(3) formatted
     * hash string of length=60.
     * 
     * The bcrypt workload (i.e. BCRYPT_WORKLOAD) is specified in the above static variable, a value from 10 to 31.
     * A workload of 12 is a very reasonable safe default as of 2013.
     * 
     * This automatically handles secure 128-bit salt generation and storage within the hash.
     * 
     * @param plaintextPassowrd the plaintext password to hash
     * @param salt              salt for BCrypt hash function. Use getBCryptSalt() to return dedicated strong salt for BCrypt hash.
     * @return String           a string of length 60 that represents the BCrypt hashed password
     */
    public static String bCryptHashPassword(String plaintextPassowrd, String salt) {
        return BCrypt.hashpw(plaintextPassowrd, salt);
    }
    
    public static String getBCryptSalt() {
        return BCrypt.gensalt( BCRYPT_WORKLOAD );
    }
    
    public static boolean isHashFunctionSupported(HashFunctionEnum hashFunctionEnum ) {
        if ( hashFunctionEnum == null ) {
            return false;
        }
        return !unsupportedHashFunctionList.contains( hashFunctionEnum );  
    }

    /**
     * Return random generated salt. This should be a pretty good salt. See  
     * https://www.cigital.com/blog/proper-use-of-javas-securerandom/ for why.
     * 
     * @return Base64 encoded salt for hashing data.
     * 
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws UnsupportedEncodingException 
     */
    public static String getSalt() throws NoSuchAlgorithmException, NoSuchProviderException, UnsupportedEncodingException
    {
        // Always specify the exact PRNG and provider that you wish to use else may end up with weaker implementation
        // of PRNG in different platforms
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG", "SUN");
        
        byte[] saltBytes = new byte[16];
        
        // always call SecureRandom.nextBytes(byte[]) immediately after creating a new instance of the PRNG
        secureRandom.nextBytes( saltBytes );
        
        // return base64 encoded string
        return new String( Base64.encode( saltBytes ), UTF8);
    }
}

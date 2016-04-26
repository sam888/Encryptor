package crypto.encryptor.util;

import crypto.encryptor.enums.HashFunctionEnum;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * @author Samuel Huang
 * Date: 13/04/2016
 */
public class HashFunctionUtilTest {
    
    private String key = "0003015802";
    private String value1 = "ABC";
    private String value2 = "DDT";
    
    /**
     * Remember, unit tests are for amateur. A real pro simply wins it... ;) 
     */
    
    public HashFunctionUtilTest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() {
    }
    
    @After
    public void tearDown() {
    }

    /**
     * Verify MD5 hash works as expected. Use online hash functions generator to verify 
     * expected value.
     */
    @Test
    public void testMd5_success() throws Exception {

        String expectedHashedValue1 = "A62BB506AA97AFB215218F294A1596E5";
        String expectedHashedValue2 = "4AA2CDB5D1D88992543E8CBE04227622";
        
        assertEquals(expectedHashedValue1, HashFunctionUtil.hash(key, value1, HashFunctionEnum.MD5));
        assertEquals(expectedHashedValue2, HashFunctionUtil.hash(key, value2, HashFunctionEnum.MD5));
    }
    
    
    /**
     * Verify SHA-1 hash works as expected. Use online hash functions generator to verify expected value.
     */
    @Test
    public void testSHA1_success() throws Exception {
       
        String key = "0003015802";
        String value1 = "ABC";
        String value2 = "DDT";
        
        String expectedHashedValue1 = "B57F30C248A553BBD6883C5223B4B634867FAD6B";
        String expectedHashedValue2 = "EDD5708A8B4B8C5CB8466DDA8F82784D5FDF96D2";
        
        assertEquals(expectedHashedValue1, HashFunctionUtil.hash(key, value1, HashFunctionEnum.SHA1));
        assertEquals(expectedHashedValue2, HashFunctionUtil.hash(key, value2, HashFunctionEnum.SHA1));
    }
    
    /**
     * Verify SHA-256 hash works as expected. Use online hash functions generator to verify expected value.
     */
    @Test
    public void testSHA256_success() throws Exception {
       
        String key = "0003015802";
        String value1 = "ABC";
        String value2 = "DDT";
        
        String expectedHashedValue1 = "B1F08FCEE64A916B80E2787E4280194CF40813D83D8E58F0B89A45F687429650";
        String expectedHashedValue2 = "64C10D18C125CEB8120E05A49D6FF7447C01228B10409F2C4C213238B27FDAA6";
        
        assertEquals(expectedHashedValue1, HashFunctionUtil.hash(key, value1, HashFunctionEnum.SHA256));
        assertEquals(expectedHashedValue2, HashFunctionUtil.hash(key, value2, HashFunctionEnum.SHA256));
    }

    /**
     * Verify UnsupportedException will be thrown for unsupported Hash function
     */
    @Test( expected = UnsupportedOperationException.class )
    public void test_throwException_forUnsupportedHash_success() throws Exception {
        
        HashFunctionUtil.hash("aaa", "bbbb", HashFunctionEnum.BCRYPT );
    }

    
}

package crypto.encryptor.enums;

/**
 * Created with IntelliJ IDEA.
 * User: Samuel Huang
 * Date: 14/09/13
 */
public enum CipherEngineEnum {

    AES("AES"), RIJNDAEL("RIJNDAEL"), TWO_FISH("TwoFish");
    
    private String cipherName;
    
    private CipherEngineEnum(String cipherName) {
        this.cipherName = cipherName;
    }
    
    public String value() {
        return cipherName;
    }

    public static boolean contains(String cipherEngine) {
        for ( CipherEngineEnum cipherEngineEnum: values() ) {
           if ( cipherEngineEnum.value().equals( cipherEngine ) ) {
               return true;
           }
        }
        return false;
    }
    
    public static CipherEngineEnum get(String cipherName) {
        for ( CipherEngineEnum cipherEngineEnum: values() ) {
           if ( cipherEngineEnum.value().equalsIgnoreCase(cipherName ) ) {
               return cipherEngineEnum;
           }
        }
        return null;
    }
}

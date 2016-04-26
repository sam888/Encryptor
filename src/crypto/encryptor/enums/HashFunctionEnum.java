/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package crypto.encryptor.enums;

/**
 *
 * @author Samuel Huang
 * Date: 12/04/2016
 * 
 */
public enum HashFunctionEnum {
    
    MD5("MD5"), SHA1("SHA-1"), SHA256("SHA-256"), BCRYPT("BCRYPT");

    private String hashFunction;

    private HashFunctionEnum(String hashFunction) {
        this.hashFunction = hashFunction;
    }
    
    public String value() {
        return hashFunction;
    }

    public static boolean contains( String hashFunction ) {
        for ( HashFunctionEnum hashFunctionEnum: values() ) {
           if ( hashFunctionEnum.value().equals( hashFunction ) ) {
               return true;
           }
        }
        return false;
    }
    
    public static HashFunctionEnum get(String hashFunction) {
        for ( HashFunctionEnum hashFunctionEnum: values() ) {
           if ( hashFunctionEnum.value().equalsIgnoreCase( hashFunction)) {
               return hashFunctionEnum;
           }
        }
        return null;
    }
}

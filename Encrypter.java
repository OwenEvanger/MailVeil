/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package SMIME;

import ASN1.ASNEncoder;
import CMS.AlgorithmIdentifier;
import CMS.CMSEncoder;
import CMS.ContentEncryptionAlgorithmIdentifier;
import CMS.ContentType;
import CMS.EncryptedContent;
import CMS.EncryptedContentInfo;
import Utilities.ByteArrayProcessor;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 *
 * @author Owen
 */
public class Encrypter {
    ASNEncoder asn = new ASNEncoder();
    //Used to encrypt the content of an internal parresia.ca message.
    CMSEncoder encoder = new CMSEncoder();
    
    ByteArrayProcessor mProcessor = new ByteArrayProcessor();
    
    public Encrypter(){
        
    }
    
    /** encryptAES() encodes the message data into a CMS encryptedData object then wraps it in a CMS contentInfo object. 
     * This method only uses AES256 for its encryption.
     * with CBC.
     * 
     * @param message - The message to encrypt
     * @param key - The private key of the user
     * @return byte[] - The encoded contentInfo object.
     * @since 1.0
     */
    public byte[] encryptAES(byte[] message, PrivateKey key){
        System.out.println("encryptAES(): Method called.");
        //RFC 3565:
        
        EncryptedContentInfo info = new EncryptedContentInfo();
        ContentType type = new ContentType();
        
        //id-encryptededData OBJECT IDENTIFIER ::= {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs7(7) 6}       
        // {1 2 840 113549 1 7 6}
        // sub identifiers {42 840 113549 1 7 6}       
        ArrayList<Integer> encrypted_oid_list = new ArrayList<>(Arrays.asList(42, 840, 113549, 1, 7, 6));
        
        type.setContentType(encrypted_oid_list);
        
        //Add ContentType to EncryptedContentInfo
        info.setContentType(type);
        
        //Now we do the AlgorithmIdentifier for the encryption algorithm (AES)
        AlgorithmIdentifier aes_algorithm = new AlgorithmIdentifier();
        
        ArrayList<Integer> aes_oid_list = new ArrayList<>(Arrays.asList(96, 840, 1, 101, 3, 4, 1, 42)); //RFC 3565 AES 
        aes_algorithm.setObjectIdentifier(aes_oid_list);
        
        //Determine our IV
        SecureRandom rand = new SecureRandom();
        byte[] iv = new byte[16]; //IV is sent as Encryption Algorithm parameter in CMS
        rand.nextBytes(iv);
        
        //Encode the IV as the algorithm param
        //RFC 3565
        //AES-IV ::= OCTET STRING (SIZE(16))
        byte[] params = asn.encodeOctetString(iv);
        
        //Add the params
        aes_algorithm.setParams(params);
        
        ContentEncryptionAlgorithmIdentifier encryption_algorithm = new ContentEncryptionAlgorithmIdentifier();
        encryption_algorithm.setContentEncryptionAlgorithmIdentifier(aes_algorithm);
        
        //Add the encryption algorithm to EncryptedContentInfo
        //TODO: We add the IV as a param - RFC 3565
        info.setContentEncryptionAlgorithmIdentifier(encryption_algorithm);
        
        //Get our encrypted content
        EncryptedContent content = new EncryptedContent();
        
        //Encrypt the data
        byte[] encrypted_bytes = encrypt(message, key, iv, "RSA/ECB/PKCS1Padding", "AES/CBC/PKCS5Padding");
        
        if(encrypted_bytes == null){
            System.out.println("encryptAES(): Encrypting the bytes failed.");
            //throw exception
            return null;
        }
        
        content.setEncryptedContent(encrypted_bytes);
        
        //Add the encrypted content to EncryptedContentInfo
        info.setEncryptedContent(content);
        
        byte[] encrypted_data = encoder.encodeEncryptedData(3, info, null);
        
        //Wrap it in a ContentInfo object
        return encoder.encodeContentInfo("id-encryptedData", encrypted_data);
    }
    
    /** encrypt() encrypts the passed in bytes.
     * 
     * @param bytes
     * @param pvt The private key
     * @param iv The initialization vector
     * @param key_cipher_alg The name of the key cipher alg
     * @param main_cipher_alg The name of the main cipher alg
     * @return The encrypted bytes
     * @since 1.0
     */
    public byte[] encrypt(byte[] bytes, PrivateKey pvt, byte[] iv, String key_cipher_alg, String main_cipher_alg){
        System.out.println("encrypt(): Method called.");
        
        try{
            ArrayList<byte[]> list = new ArrayList<>();
            KeyGenerator gen = KeyGenerator.getInstance("AES");
            gen.init(128);
            SecretKey sec = gen.generateKey();

            Cipher key_cipher = Cipher.getInstance(key_cipher_alg);  //This alg is known before hand
            key_cipher.init(Cipher.ENCRYPT_MODE, pvt);
            byte[] encrypted_key = key_cipher.doFinal(sec.getEncoded());
            System.out.println("encrypt(): Adding the encrypted key.");
            list.add(encrypted_key);

            
            IvParameterSpec iv_spec = new IvParameterSpec(iv);
            System.out.println("encrypt(): Adding the IV.");
            list.add(iv);

            Cipher main_cipher = Cipher.getInstance(main_cipher_alg);
            main_cipher.init(Cipher.ENCRYPT_MODE, sec, iv_spec);
            System.out.println("encrypt(): Adding the encrypted data.");
            list.add(main_cipher.doFinal(bytes));
            
            return mProcessor.compileArrays(list);
        }catch(NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException 
                | BadPaddingException | InvalidAlgorithmParameterException e){
            System.out.println("encrypt(): Exception thrown.");
        }
        return null;
    }
}

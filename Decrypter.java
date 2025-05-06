/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package SMIME;

import CMS.CMSDecoder;
import CMS.ContentInfo;
import CMS.EncryptedData;
import CMS.SignedData;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Owen
 */
public class Decrypter {
    
    public Decrypter(){
        
    }
    
    /** decryptAES() decodes the encryptedData object within the contentInfo object. Once the decoding is finished we use the provided
     * information to decrypt the internal message and return it. 
     * This method accompanies the encryptAES() method of Encrypter.java.
     *
     * @param data The encoded ContentInfo object
     * @param key - The public key of the user who encrypted the message.
     * @return byte[] The decrypted message
     * @since 1.0
     */
    public byte[] decryptAES(byte[] data, PublicKey key){
        System.out.println("decryptAES(): Method called.");
        CMSDecoder decoder = new CMSDecoder();
        
        ContentInfo ci = decoder.decodeContentInfo(data);
        if(ci == null){
            System.out.println("decryptAES(): ContentInfo was null.");
            return null;
        }
        
        EncryptedData sd = decoder.decodeEncryptedData(ci);
        if(sd == null){
            System.out.println("decryptAES(): EncryptedData was null.");
            return null;
        }
        
        //Extract the encrypted content
        byte[] content = sd.getEncryptedContentInfo().getEncryptedContent().getEncryptedContent();
        if(content == null){
            System.out.println("decryptAES(): EncryptedContent was null.");
            return null;
        }
        //String alg_name = sd.getEncryptedContentInfo().getContentEncryptionAlgorithmIdentifier().getContentEncryptionAlgorithmIdentifier().getName();
        
        return decrypt(content, key, "RSA/ECB/PKCS1Padding", "AES/CBC/PKCS5Padding");
    }
    
    /** decrypt() is used to decrypt the passed in bytes.
     * 
     * @param bytes The bytes to decrypt
     * @param key The public key
     * @param key_cipher_alg The name of the key cipher alg (RSA/ECB/PKCS1Padding).
     * @param main_cipher_alg The name of the main cipher alg (AES/CBC/PKCS5Padding).
     * @return The decrypted bytes
     * @since 1.0
     */
    public byte[] decrypt(byte[] bytes, PublicKey key, String key_cipher_alg, String main_cipher_alg){
        System.out.println("decrypt(): Method called.");
        try{
            //Start with the cipher
            Cipher key_cipher = Cipher.getInstance(key_cipher_alg);
            key_cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] b = new byte[256];
            System.arraycopy(bytes, 0, b, 0, 256); //Isolate the key
            byte[] key_b = key_cipher.doFinal(b);
            SecretKeySpec secret_key = new SecretKeySpec(key_b, "AES");

            byte[] init_vect = new byte[16]; 
            System.arraycopy(bytes, 256, init_vect, 0, 16);
            IvParameterSpec ivspec = new IvParameterSpec(init_vect);

            Cipher cipher = Cipher.getInstance(main_cipher_alg);
            cipher.init(Cipher.DECRYPT_MODE, secret_key, ivspec);

            byte[] final_bytes = new byte[bytes.length - 272];
            System.arraycopy(bytes, 272, final_bytes, 0, (bytes.length - 272));
            return cipher.doFinal(final_bytes); //NOTE: Check if this needs to be all of the bytes or bytes with the first (256 + 16)
            //bytes removed.

        }catch(NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | ArrayIndexOutOfBoundsException
                    | BadPaddingException | InvalidAlgorithmParameterException | NoSuchAlgorithmException e){
            //Policy
            System.out.println("decrypt(): Decryption failed.");
        }
        return null;
    }
}

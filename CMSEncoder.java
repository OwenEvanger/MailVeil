/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package CMS;

import ASN1.ASNEncoder;
import Utilities.ByteArrayProcessor;
import Utilities.Utilities;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Stack;


/**
 * RFC 3852 Cryptographic Message Syntax
 * @author Owen
 */
//TODO: IMPLICIT and EXPLICIT tags
public class CMSEncoder {
    ASNEncoder encoder = new ASNEncoder();
    
    Utilities mUtils = new Utilities();
    
    ByteArrayProcessor processor = new ByteArrayProcessor();
    
    public byte[] encodeContentInfo(String type, byte[] content){
        System.out.println("encodeContentInfo(): Method called.");
        //Content-Info ::= SEQUENCE {
        //    contentType ContentType,
        //    content [0] EXPLICIT ANY DEFINED BY contentType }
        ArrayList<byte[]> list = new ArrayList<>();
        byte[] ct = encodeContentType(type);
        if(ct == null){
            System.out.println("encodeContentInfo(): Content type returned null.");
            return null;
        }
        list.add(ct);
        
        //The explicit tag 0 is wrapped over the content object.
        byte[] con = encoder.encodeExplicitTag(content, 0);
        list.add(con);
        
        return encoder.encodeSEQUENCE(processor.compileArrays(list));
    }
    
    /** encodeEncryptedData() encodes the EncryptedData object.
     * 
     * @param version
     * @param info
     * @param attrs
     * @return The EncryptedData object
     */
    public byte[] encodeEncryptedData(int version, EncryptedContentInfo info, UnprotectedAttributes attrs){
        System.out.println("encodeEncryptedData(): Method called.");
        //EncryptedData ::= SEQUENCE {
        //    version CMSVersion,
        //    encryptedContentInfo EncryptedContentInfo,
        //    unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL}
        ArrayList<byte[]> list = new ArrayList<>();
        
        byte[] encoded_version = encodeCMSVersion(version);
        if(encoded_version == null){
            System.out.println("encodeEncryptedData(): CMSVersion encoding failed.");
            return null;
        }
        list.add(encoded_version);
        
        byte[] encoded_content = encodeEncryptedContentInfo(info, "id-encryptedData");
        if(encoded_content == null){
            System.out.println("encodeEncryptedData(): Encrypted content info encoding failed.");
            return null;
        }
        list.add(encoded_content);
        
        //Ignore UnprotectedAttributes for now
        if(attrs != null){
            //Not supported yet
        }
        
        return encoder.encodeSEQUENCE(processor.compileArrays(list));
    }
    
    /** encodeEncryptedContentInfo() encodes the EncryptedContentInfo object.
     * 
     * @param info
     * @param content_type
     * @return The encoded EncryptedContentInfo object
     * @since 1.0
     */
    public byte[] encodeEncryptedContentInfo(EncryptedContentInfo info,String content_type){
        System.out.println("encodeEncryptedContentInfo(): Method called.");
        //EncryptedContentInfo ::= SEQUENCE {
        //    contentType ContentType,
        //    contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
        //    encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }
        ArrayList<byte[]> list = new ArrayList<>();
        
        byte[] encode_type = encodeContentType(content_type);
        if(encode_type == null){
            System.out.println("encodeEncryptedContentInfo(): Content type was null.");
            return null;
        }
        list.add(encode_type);
        
        byte[] ai = encodeContentEncryptionAlgorithmIdentifier(info.getContentEncryptionAlgorithmIdentifier().getContentEncryptionAlgorithmIdentifier());
        if(ai == null){
            System.out.println("encodeEncryptedContentInfo(): Algorithm ID was null.");
            return null;
        }
        list.add(ai);
        
        //We encode the EncryptedContent as an IMPLICIT OCTET STRING with tag 0.
        byte[] enc = encoder.encodeIMPLICITOctetString(info.getEncryptedContent().getEncryptedContent(), 0);
        if(enc == null){
            System.out.println("encodeEncryptedContentInfo(): EncryptedContent was null.");
            return null;
        }
        list.add(enc);
        
        return encoder.encodeSEQUENCE(processor.compileArrays(list));
    }
    
    
    public byte[] encodeSignedData(int version, ArrayList<AlgorithmIdentifier> digest_algorithms, String content_type, byte[] content,
            ArrayList<SignerInfo> infos){
        System.out.println("encodeSignedData(): Method called.");
        /* SignedData ::= SEQUENCE {
        **    version           CMSVersion,
        **    digestAlgorithms  DigestAlgorithmIdentifiers,
        **    encapContentInfo  EncapsulatedContentInfo,
        **    certificates [0] IMPLICIT CertificateSet OPTIONAL,
        **    crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
        **    signerInfos SignerInfos }
        */
        
        ArrayList<byte[]> list = new ArrayList<>();
        
        byte[] encoded_version = encodeCMSVersion(version);
        if(encoded_version == null){
            System.out.println("encodeSignedData(): Version encoding failed.");
            return null;
        }
        list.add(encoded_version);
        
        byte[] encoded_ai = encodeDigestAlgorithmIdentifiers(digest_algorithms);
        if(encoded_ai == null){
            System.out.println("encodeSignedData(): DigestAlgorithmIdentifier encoding failed.");
            return null;
        }
        list.add(encoded_ai);
        
        byte[] encoded_ci = encodeEncapsulatedContentInfo(content, content_type);
        if(encoded_ci == null){
            System.out.println("encodeSignedData(): EncapsulatedContentInfo encoding failed.");
            return null;
        }
        list.add(encoded_ci);  
        
        //list.add(encodeCertificateSet());  //OPTIONAL
        
        //list.add(encodeRevocationInfoChoices());  //OPTIONAL
        
        byte[] encoded_si = encodeSignerInfos(infos);
        if(encoded_si == null){
            System.out.println("encodeSignedData(): SignerInfos encoding failed.");
            return null;
        }
        list.add(encoded_si);
        
        //Now we have all of the types encoded. Compile the arrays, and encode a sequence.
        return encoder.encodeSEQUENCE(processor.compileArrays(list));
    }
    
    public byte[] encodeCMSVersion(int version){
        //CMSVersion = INTEGER {v0(0), v1(1), v2(2), v3(3), v4(4), v5(5)}
        System.out.println("encodeCMSVersion(): Method called.");
        if(version < 0 || version > 5){
            System.out.println("encodeCMSVersion(): Version number out of bounds.");
        }
        return encoder.encodeInteger(version);
    }
    
    public byte[] encodeDigestAlgorithmIdentifiers(ArrayList<AlgorithmIdentifier> list){
        System.out.println("encodeDigestAlgorithmIdentifiers(): Method called.");
        //SET OF DigestAlgorithmIdentifier
        ArrayList<byte[]> results = new ArrayList<>();
        
        for(AlgorithmIdentifier item : list){
            byte[] id = encodeDigestAlgorithmIdentifier(item);
            if(id == null){
                System.out.println("encodeDigestAlgorithmIdentifiers(): Error encoding AlgorithmIdentifier.");
                return null;
            }
            results.add(id);
        }
        byte[] bytes = processor.compileArrays(results);
        
        //Now we encode the SET OF
        return encoder.encodeSETOF(bytes);
    }
    
    /* encodeEncapsulatedContentInfo() takes as input the signed content and formats it into an encoded octet string. It also takes the 
    ** content type.
    **
    */
    public byte[] encodeEncapsulatedContentInfo(byte[] content, String content_type){
        System.out.println("encodeEncapsulatedContentInfo(): Method called.");
        //EncapsulatedContentInfo ::= SEQUENCE {
        //  eContentType ContentType,
        //  eContent[0] EXPLICIT OCTET STRING OPTIONAL }
        //int content_type = 0;
        ArrayList<byte[]> list = new ArrayList<>();
        
        byte[] eContentType = encodeContentType(content_type);
        if(eContentType == null){
            System.out.println("encodeEncapsulatedContentInfo(): ContentType encoding error.");
            return null;
        }
        list.add(eContentType);
        
        //We encode the OCTET STRING then encode the results with the EXPLICIT tag [0].
        byte[] eContents = encoder.encodeExplicitTag(encoder.encodeOctetString(content), 0);
        if(eContents == null){
            System.out.println("encodeEncapsulatedContentInfo(): Contents encoding error.");
            return null;
        }
        list.add(eContents);
        
        return encoder.encodeSEQUENCE(processor.compileArrays(list));
    }
    
    /** encodeContentType() encodes the recognized content types and returns the encoded object identifiers.
     * 
     * @param type The specification's name for the content type
     * @return The encoded object identifier
     * @since 1.0
     */
    public byte[] encodeContentType(String type){
        System.out.println("encodeContentType(): Method called.");
        //Content-Type ::= OBJECT IDENTIFIER
        switch(type){
            case "id-data":
                //id-data: 1, 2, 840, 113549, 1, 7, 1
                ArrayList<Integer> data_subs = new ArrayList<>(Arrays.asList(42,840, 113549, 1, 7, 1));
                return encodeObjectIdentifier(data_subs);
            
            case "id-signedData":
                //id-signedData: 1, 2, 840, 113549, 1, 7, 2
                ArrayList<Integer> signed_subs = new ArrayList<>(Arrays.asList(42,840, 113549, 1, 7, 2));
                return encodeObjectIdentifier(signed_subs);
                
            case "id-envelopedData":
                //id-envelopedData: 1, 2, 840, 113549, 1, 7, 3
                ArrayList<Integer> enveloped_subs = new ArrayList<>(Arrays.asList(42,840, 113549, 1, 7, 3));
                return encodeObjectIdentifier(enveloped_subs);
                
            case "id-digestedData":
                //id-digestedData: 1, 2, 840, 113549, 1, 7, 5
                ArrayList<Integer> digested_subs = new ArrayList<>(Arrays.asList(42,840, 113549, 1, 7, 5));
                return encodeObjectIdentifier(digested_subs);
                
            case "id-encryptedData":
                //id-encryptedData: 1, 2, 840, 113549, 1, 7, 6
                ArrayList<Integer> encrypted_subs = new ArrayList<>(Arrays.asList(42,840, 113549, 1, 7, 6));
                return encodeObjectIdentifier(encrypted_subs);
                
            case "id-authData":
                //id-authData: 1, 2, 840, 113549, 1, 9, 16, 1, 2
                ArrayList<Integer> auth_subs = new ArrayList<>(Arrays.asList(42,840, 113549, 1, 9, 16, 1, 2));
                return encodeObjectIdentifier(auth_subs);
                
            default:
                System.out.println("encodeContentType(): Type not recognized. Returning null.");
                return null;
        }
        
    }
    
    public byte[] encodeCertificateSet(){
        return null;
    }
    
    public byte[] encodeRevocationInfoChoices(){
        return null;
    }
    
    public byte[] encodeSignerInfos(ArrayList<SignerInfo> infos){
        System.out.println("encodeSignerInfos(): Method called.");
        //SignerInfos ::= SET OF SignerInfo
        
        ArrayList<byte[]> list = new ArrayList<>();
        for(SignerInfo info : infos){
            byte[] encoded_info = encodeSignerInfo(info.getCMSVersion(), info.getSignerIdentifier().getSubjectKeyIdentifier(), info.getDigestAlgorithmIdentifier(),
                    info.getSignedAttributes(), info.getSignature(), info.getSignatureAlgorithmIdentifier(), null);
            if(encoded_info == null){
                System.out.println("encodeSignerInfos(): SignerInfo encoding failed.");
                return null;
            }
            list.add(encoded_info);  
        }
        
        return encoder.encodeSETOF(processor.compileArrays(list));
    }
    
    public byte[] encodeSignerInfo(int version, byte[] certificate_id, AlgorithmIdentifier digest_algorithm, ArrayList<Attribute> signed_attributes,
            byte[] signature, AlgorithmIdentifier signature_algorithm, ArrayList<Attribute> unsigned_attributes){
        System.out.println("encodeSingerInfo(): Method called.");
        //CMS 
        //SignerInfo ::= SEQUENCE {
        //  version CMSVersion,
        //  sid SignerIdentifier,
        //  digestAlgorithm DigestAlgorithmIdentifier,
        //  signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
        //  signatureAlgorithm SignatureAlgorithmIdentifier,
        //  signature SignatureValue,
        //  unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
        ArrayList<byte[]> list = new ArrayList<>();
        
        byte[] encoded_version = encodeCMSVersion(version);
        if(encoded_version == null){
            System.out.println("encodeSignerInfo(): CMSVersion encoding failed.");
            return null;
        }
        list.add(encoded_version);
        
        byte[] encoded_si = encodeSignerIdentifier(certificate_id);
        if(encoded_si == null){
            System.out.println("encodeSignerInfo(): SignerIdentifier encoding failed.");
            return null;
        }
        list.add(encoded_si);
        
        byte[] encoded_ai = encodeDigestAlgorithmIdentifier(digest_algorithm);
        if(encoded_ai == null){
            System.out.println("encodeSignerInfo(): DigestAlgorithmIdentifier encoding failed.");
            return null;
        }
        list.add(encoded_ai);
        
        if(signed_attributes != null){
            //list.add(encodeSignedAttributes(signed_attributes));
        }
        
        byte[] encoded_sai = encodeSignatureAlgorithmIdentifier(signature_algorithm);
        if(encoded_sai == null){
            System.out.println("encodeSignerInfo(): SignatureAlgorithmIdentifier encoding failed.");
            return null;
        }
        list.add(encoded_sai);
        
        byte[] encoded_signature = encodeSignatureValue(signature);
        if(encoded_signature == null){
            System.out.println("encodeSignerInfo(): SignatureValue encoding failed.");
            return null;
        }
        list.add(encoded_signature);
        
        if(unsigned_attributes != null){
            //list.add(encodeUnsignedAttributes(unsigned_attributes));
        }
        System.out.println("encodeSignerInfo(): Encoding the sequence.");
        return encoder.encodeSEQUENCE(processor.compileArrays(list));
    }
    
    public byte[] encodeSignerIdentifier(byte[] subject){
        System.out.println("encodeSignerIdentifier(): Method called.");
        //SignerIdentifier ::= CHOICE {
        //  issuerAndSerialNumber IssuerAndSerialNumber,
        //  subjectKeyIdentifier [0] SubjectKeyIdentifier }
        
        //My initial thought is to use the issuer and serial number on the certificate. That being said I need to add more code to integrate 
        //X.501 so i'll do the subject id for now.
        
        //TODO: Swap to serial number?
        //SubjectKeyIdentifier ::= OCTET STRING
        byte[] encoding = encoder.encodeExplicitTag(encoder.encodeOctetString(subject), 0);
        
        //CHOICE encoding 
        return encoder.encodeCHOICE(encoding);
    }
    
    public byte[] encodeSignedAttributes(byte[] attributes){
        //SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
        //Attribute ::= SEQUENCE {
        //  attrType OBJECT IDENTIFIER,
        //  attrValues SET OF AttributeValue }
        
        //AttributeValue ::= ANY
        
        //How we proceed depends on the format of the attributes byte array. I'll just lay out the two encodings for now.
        ArrayList<byte[]> list = new ArrayList<>();
        
        byte[] id = encodeObjectIdentifier(null);
        list.add(id);
        
        byte[] any  = encoder.encodeANY(null);
        list.add(id);
        
        byte[] attribute = encoder.encodeSEQUENCE(processor.compileArrays(list));
        
        return encoder.encodeSETOF(attribute); //
    }
    
    public byte[] encodeSignatureAlgorithmIdentifier(AlgorithmIdentifier alg){
        System.out.println("encodeSignatureAlgorithmIdentifier(): Method called.");
        //SignatureAlgorithmIdentifier ::= AlgorithmIdentifier
        AlgorithmIdentifier id = new AlgorithmIdentifier();
        if(alg.getObjectIdentifier() == null || alg.getObjectIdentifier().isEmpty()){
            String algorithm = alg.getName();
            switch(algorithm){
                case "sha256WithRSAEncryption":
                    //OBJECT IDENTIFIER: 1.2.840.113549.1.1.11
                    ArrayList<Integer> subs = new ArrayList<>(Arrays.asList(42,840, 113549, 1, 1, 11));
                    id.setObjectIdentifier(subs);
                    break;

                default:
                    System.out.println("encodeSignatureAlgorithmIdentifier(): Algorithm name not recognized.");
                    return null;
            }
        }else{
            id.setObjectIdentifier(alg.getObjectIdentifier());
        }
        return encodeAlgorithmIdentifier(id);
    }
    
    public byte[] encodeDigestAlgorithmIdentifier(AlgorithmIdentifier alg){
        System.out.println("encodeDigestAlgorithmIdentifier(): Method called.");
        //DigestAlgorithmIdentifier ::= AlgorithmIdentifier
        AlgorithmIdentifier id = new AlgorithmIdentifier();
        
        //See if we have an OID, otherwise we go off name
        if(alg.getObjectIdentifier() == null || alg.getObjectIdentifier().isEmpty()){
            String algorithm = alg.getName();
            switch(algorithm){
                case "SHA-256":
                    //OBJECT IDENTIFIER: 2.16.840.1.101.3.4.2.1
                    ArrayList<Integer> subs = new ArrayList<>(Arrays.asList(96, 840, 1, 101, 3, 4, 2, 1));
                    id.setObjectIdentifier(subs);
                    break;

                default: 
                    System.out.println("encodeDigestAlgorithmIdentifier(): ID name was not recognized.");
                    return null;
            }
        }else{
            //Take the OID from alg and set it in id
            id.setObjectIdentifier(alg.getObjectIdentifier());
        }
        return encodeAlgorithmIdentifier(id);
    }
    
    public byte[] encodeContentEncryptionAlgorithmIdentifier(AlgorithmIdentifier alg){
        System.out.println("encodeContentEncryptionAlgorithmIdentifier(): Method called.");
        AlgorithmIdentifier id = new AlgorithmIdentifier();
        if(alg.getObjectIdentifier() == null || alg.getObjectIdentifier().isEmpty()){
            System.out.println("encodeContentEncryptionAlgorithmIdentifier(): No oid provided. Going off name.");
            //We go off the provided name
            String algorithm = alg.getName();
            switch(algorithm){
                case "AES256/CBC":
                    id.setObjectIdentifier(alg.getObjectIdentifier());
                    break;

                default:
                    return null;
            }
        }else{
            System.out.println("encodeContentEncryptionAlgorithmIdentifier(): Adding the oid.");
            //We use the provided oid
            id.setObjectIdentifier(alg.getObjectIdentifier());
        }
        return encodeAlgorithmIdentifier(id);
    }
    
    public byte[] encodeSignatureValue(byte[] signature){
        System.out.println("encodeSignatureValue(): Method called.");
        //SignatureValue ::= OCTET STRING
        return encoder.encodeOctetString(signature);
    }
    
    public byte[] encodeUnsignedAttributes(byte[] attributes){
        //UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
        return encodeSignedAttributes(attributes);
    }
    
    public byte[] encodeAlgorithmIdentifier(AlgorithmIdentifier id){
        System.out.println("encodeAlgorithmIdentifier(): Method called.");
        //SEQUENCE
        //AlgorithmIdentifier ::= SEQUENCE {
        //  algorithm   OBJECT IDENTIFIER
        //  parameters  ANY DEFINED BY algorithm OPTIONAL }
        
        //In this sequence we have an OBJECT IDENTIFIER and NULL for the params.
        ArrayList<byte[]> list = new ArrayList<>();
        //Add the OID
        byte[] contents = encodeObjectIdentifier(id.getObjectIdentifier());
        list.add(contents);
        //If there are no params we add NULL 
        if(id.getParams() == null){
            System.out.println("encodeAlgorithmIdentifier(): No params, adding NULL.");
            //Add the NULL params
            byte[] nll = encoder.encodeNull();
            list.add(nll);
        }else{
            System.out.println("encodeAlgorithmIdentifier(): Params found.");
            //We directly place the already encoded params into the list
            list.add(id.getParams());
        }
        return encoder.encodeSEQUENCE(processor.compileArrays(list));
    }
    
    
    
    /*----------- OBJECT IDENTIFIER encodings ---------------*/
    
    public byte[] encodeContentInfoIdentifierOI(){
        //RFC 3852
        //id-ct-contentInfo OBJECT IDENTIFIER ::= {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9) smime(16) ct(1) 6}
        
        // {1 2 840 113549 1 9 16 1 6}
        // sub identifiers {42 840 113549 1 9 16 1 6}
        
        ArrayList<Integer> list = new ArrayList<>();
        list.add(42);
        list.add(840);
        list.add(113549);
        list.add(1);
        list.add(9);
        list.add(16);
        list.add(1);
        list.add(6);       
        
        return encodeObjectIdentifier(list);
    }
    
    public byte[] encodeDataOI(){
        //RFC 3852
        //id-data OBJECT IDENTIFIER ::= {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs7(7) 1}
        
        // {1 2 840 113549 1 7 1}
        // sub identifiers {42 840 113549 1 7 1}
        
        ArrayList<Integer> list = new ArrayList<>();
        list.add(42);
        list.add(840);
        list.add(113549);
        list.add(1);
        list.add(7);
        list.add(1);       
        
        return encodeObjectIdentifier(list);
    }
    
    public byte[] encodeSignedDataOI(){
        //RFC 3852
        //id-signedData OBJECT IDENTIFIER ::= {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs7(7) 2}
        
        // {1 2 840 113549 1 7 2}
        // sub identifiers {42 840 113549 1 7 2}
        
        ArrayList<Integer> list = new ArrayList<>();
        list.add(42);
        list.add(840);
        list.add(113549);
        list.add(1);
        list.add(7);
        list.add(2);       
        
        return encodeObjectIdentifier(list);
    }
    
    public byte[] encodeEnvelopedData(){
        //RFC 3852
        //id-envelopedData OBJECT IDENTIFIER ::= {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs7(7) 3}
        
        // {1 2 840 113549 1 7 3}
        // sub identifiers {42 840 113549 1 7 3}
        
        ArrayList<Integer> list = new ArrayList<>();
        list.add(42);
        list.add(840);
        list.add(113549);
        list.add(1);
        list.add(7);
        list.add(3);       
        
        return encodeObjectIdentifier(list);
    }
    
    public byte[] encodeDigestedData(){
        //RFC 3852
        //id-digestedData OBJECT IDENTIFIER ::= {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs7(7) 5}
        
        // {1 2 840 113549 1 7 5}
        // sub identifiers {42 840 113549 1 7 5}
        
        ArrayList<Integer> list = new ArrayList<>();
        list.add(42);
        list.add(840);
        list.add(113549);
        list.add(1);
        list.add(7);
        list.add(5);       
        
        return encodeObjectIdentifier(list);
    }
    
    public byte[] encodeEncryptedDataOI(){
        //RFC 3852
        //id-encryptededData OBJECT IDENTIFIER ::= {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs7(7) 6}
        
        // {1 2 840 113549 1 7 6}
        // sub identifiers {42 840 113549 1 7 6}
        
        ArrayList<Integer> list = new ArrayList<>();
        list.add(42);
        list.add(840);
        list.add(113549);
        list.add(1);
        list.add(7);
        list.add(6);       
        
        return encodeObjectIdentifier(list);
    }
    
    public byte[] encodeAuthData(){
        //RFC 3852
        //id-authData OBJECT IDENTIFIER ::= {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9) smime(16) ct(1) 2}
        
        // {1 2 840 113549 1 9 16 1 2}
        // sub identifiers {42 840 113549 1 9 16 1 2}
        
        ArrayList<Integer> list = new ArrayList<>();
        list.add(42);
        list.add(840);
        list.add(113549);
        list.add(1);
        list.add(9);
        list.add(16); 
        list.add(1);
        list.add(2);
        
        return encodeObjectIdentifier(list);
    }
    
    private byte[] encodeObjectIdentifier(ArrayList<Integer> subs){
        //Generic
        ArrayList<byte[]> results = new ArrayList<>();
        byte[] b = {6};
        results.add(b);
        
        byte[] contents = encodeOIContents(subs);
        
        //Encode the length octets
        byte[] length = encoder.formatLengthOctets(contents.length);
        results.add(length);
        
        results.add(contents);
        
        return processor.compileArrays(results);
    }
    
    private byte[] encodeOIContents(ArrayList<Integer> subs){
        ArrayList<byte[]> results = new ArrayList<>();
        //We go through each entry
        for(int sub : subs){
            results.add(encodeSubidentifier(sub));
        }
        return processor.compileArrays(results);
    }
    
    //Ignore...
    public byte[] enc(int value){
        System.out.println("enc(): Method called.");
        Stack<Byte> encoded = new Stack<>();
        Stack<Integer> indices = new Stack<>();
        int remainder = value;
        
        //Our first step is to determine the bit locations (0 -> ...) from least significant (position 0) to most (position x > 0)
        //for an unsigned binary representation of the value.
        while(remainder != 0){
            //We handle the simple case of a remainder of 1
            if(remainder == 1){
                //Add bit index position 0
                indices.add(0); 
            }
            for(int i = 0;; i++){
                
                int val = (int) Math.pow(2, i);
                if(val > remainder){
                    //We stop and use the position right before this position as it is the largest value before going above the remainder.
                    indices.add(i - 1);
                    //Reduce our remainder
                    remainder -= Math.pow(2, i - 1);
                    break;
                }
            }
        }
        System.out.println("enc(): Positions are : " + indices);
        
        //The bit locations from the previous step are processed lowest to highest.
        while(!indices.isEmpty()){
            //We start with the lowest bit position
            int pos = indices.pop();
            System.out.println("enc(): Starting with bit " + pos);
            int index = 0;
            for(int t = 0;; t += 7){
                byte b = 0;
                //The index tracks the location within the encoded bytes that we will need. We do not have use of bit 8 so this helps
                //tell us where to set the bit in each local byte.
                //For ex. bit 8 (location 7) must go into the next byte if it is supposed to be set. The index value will be 7 and it will 
                //equal pos. This then tells us that position i in the local byte must be set, which for location 7 means that location 0
                //in the local byte is set.
                for(int i = 0; i < 7; i++){
                    //This loop handles the local byte's bits
                    if(index == pos){
                        //We can set the bit
                        b = mUtils.setBit(b, i);
                    }

                    index++;
                }

                //We determine if we set bit 8 (position 7). We set bit 8 for all bytes expect the first.
                if(!encoded.isEmpty()){
                    //This is not the first byte so we set bit 8 to 1.
                    b = mUtils.setBit(b, 7);
                }


                //This byte is done, add it to position 0 of the stack
                encoded.add(0, b);

            }
        }    
        //The encoded stack is now ready to convert to an array
        if(!encoded.isEmpty()){
            return null;
        }
        
        return mUtils.compile(encoded);
    }
    
    public byte[] encodeSubidentifier(int value){
        System.out.println("encodeSubidentifier(): Method called.");
        //We use bits 7 to 1. Bit 8 in each byte is 1 until we reach the last byte.
        ASNEncoder enc = new ASNEncoder();
        return enc.formatBinaryInteger(value);
    }
    
    /*------------------ Enveloped Data methods -----------------*/
    
    public byte[] encodeRecipientInfos(){
        //RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo
        return null;
    }
    
    public byte[] encodeRecipientInfo(){
        //RecipientInfo ::= CHOICE{
        //  ktri KeyTransRecipientInfo,
        //  kari [1] KeyAgreeRecipientInfo,
        //  kekri [2] KEKRecipientInfo,
        //  pwri [3] PasswordRecipientInfo,
        //  ori [4] OtherRecipientInfo }
        
        return null;
    }
    
    public byte[] encodeKeyAgreeRecipientInfo(){
        //KeyAgreeRecipientInfo ::= SEQUENCE {
        //  version CMSVersion, --always set to three
        //  originator [0] EXPLICIT OriginatorIdentifierOrKey,
        //  ukm [1] EXPLICIT UserKeyingMaterial OPTIONAL,
        //  keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
        //  recipientEncryptedKeys RecipientEncryptedKeys }
        
        return null;
    }
    
    public byte[] encodeOriginatorIdentifierOrKey(){
        //OriginatorIdentifierOrKey ::= CHOICE {
        //  issuerAndSerialNumber IssuerAndSerialNumber,
        //  subjectKeyIdentifier [0] SubjectKeyIdentifier,
        //  originatorKey [1] OriginatorPublicKey }
        
        return null;
    }

    private static class ArrayListImpl extends ArrayList<Integer> {

        public ArrayListImpl() {
        }
    }
}

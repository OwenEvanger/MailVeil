/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package X509;

import ASN1.ASNEncoder;
import Utilities.ByteArrayProcessor;
import Utilities.Utilities;

import java.util.ArrayList;


/**
 * Encoder is the main class for ASN1 encoding X509 certificates.
 * @author Owen
 * @version 1.0
 */
public class Encoder {
    //ASN encoding
    ASNEncoder encoder = new ASNEncoder();
       
    //Byte array handling
    ByteArrayProcessor mProcessor = new ByteArrayProcessor();
    
    //Standard utilities
    Utilities mUtils = new Utilities();
    
    public Encoder(){
        
    }
    
    /** encodeSignedCertificate() encodes a signed X509 certificate with the specified parameters.
     * 
     * @param version Certificate version (3)
     * @param sn Serial number of the cert
     * @param signature_id Signature algorithm
     * @param name The name of the certificate issuer (*.parresia.ca)
     * @param before The time before which the cert was not active
     * @param after The expiry date
     * @param username The name of the user for whom the certificate is generated
     * @param oid The OID for the alg used in the public key
     * @param algorithm_name The name of the alg used in the public key
     * @param public_key The public key for the user
     * @param private_key The private key for the user
     * @return The encoded Certificate
     * @since 1.0
     */
    public byte[] encodeSignedCertificate(int version, int sn, X509.AlgorithmIdentifier signature_id, String name, String before, String after, String username,
            ArrayList<Integer> oid, String algorithm_name, byte[] public_key, byte[] private_key){
        System.out.println("encodeSignedCertificate(): Method called.");
        //Certificate ::= SEQUENCE{ 
        //    tbsCertificate TBSCertificate,
        //    signatureAlgorithm AlgorithmIdentifier,
        //    signatureValue BIT STRING }
        ArrayList<byte[]> list = new ArrayList<>();
        //Lets encode the certificate
        byte[] tbs = encodeCertificate(version, sn, signature_id, name, before, after, username, oid, algorithm_name, public_key);
        list.add(tbs);
        System.out.println("encodeSignedCertificate(): The certificate has been encoded.");
        //Encode the signature alg
        byte[] alg = encodeSignatureAlgorithmIdentifier(signature_id);
        list.add(alg);
        System.out.println("encodeSignedCertificate(): The signature algorithm has been encoded.");
        //Finally, calculate then encode the signature
        byte[] signature = mUtils.signRSA(tbs, private_key);
        list.add(encoder.encodeBitString(signature, 0));
        System.out.println("encodeSignedCertificate(): The signature has been encoded.");
        return encoder.encodeSEQUENCE(mProcessor.compileArrays(list));
    }
    
    public byte[] encodeCertificate(int version, int sn, X509.AlgorithmIdentifier signature_id, String name, String before, String after, String username,
            ArrayList<Integer> oid, String algorithm_name, byte[] public_key){
        System.out.println("encodeCertificate(): Method called.");
        //TBSCertificate ::= SEQUENCE {
        //    version [0] EXPLICIT Version DEFAULT v1,
        //    serialNumber CertificateSerialNumber,
        //    signature AlgorithmIdentifier,
        //    issuer Name,
        //    validity Validity,
        //    subject Name,
        //    subjectPublicKeyInfo SubjectPublicKeyInfo,
        //    issuerUniqueID [1] IMPLICIT UniqueIdentifier OPTIONAL,
        //    subjectUniqueID [2] IMPLICIT UniqueIdentifier OPTIONAL,
        //    extensions [3] EXPLICIT Extensions OPTIONAL }
        ArrayList<byte[]> list = new ArrayList<>();
        
        //Encode the version
        list.add(encodeVersion(version));
        
        //Encode the certificate's serial number
        list.add(encodeCertificateSerialNumber(sn));
        
        //Encode the signature algorithm id
        list.add(encodeSignatureAlgorithmIdentifier(signature_id));
        
        //Encode the name of the issuer
        list.add(encodeName(name));
        
        //Encode the validity
        list.add(encodeValidity(before, after));
        
        //Encode the subject name
        list.add(encodeName(username));
        
        //Encode the public key
        list.add(encodeSubjectPublicKeyInfo(oid, name, public_key));
        
        //Finish off the certificate
        return encoder.encodeSEQUENCE(mProcessor.compileArrays(list));
    }
    
    public byte[] encodeVersion(int version){
        System.out.println("encodeVersion(): Method called.");
        //Version ::= INTEGER {v1(0), v2(1), v3(2)}
        //version is explicitly tagged with [0]
        if(version <= 0){
            //Let's just increase it and treat it as one
            version = 1;
        }
        //We decrease the version provided by one and encode that integer      
        byte[] ver = encoder.encodeInteger(--version);
        System.out.println("encodeVersion(): Integer encoded, now adding the [0] tag.");
        //Encode the EXPLICIT tag [0]
        return encoder.encodeExplicitTag(ver, 0); 
    }
    
    //NOTE: At a certain point we will need to use a sn larger than can be represented by an int.
    public byte[] encodeCertificateSerialNumber(int sn){
        System.out.println("encodeCertificateSerialNumber(): Method called.");
        //CertificateSerialNumber ::= INTEGER
        return encoder.encodeInteger(sn);
    }
    
    public byte[] encodeSignatureAlgorithmIdentifier(X509.AlgorithmIdentifier id){
        System.out.println("encodeSignatureAlgorithmIdentifier(): Method called.");
        return encodeAlgorithmIdentifier(id);
    }
    
    /*
    ** @param String name - The name as a PrintableString
    */
    public byte[] encodeName(String name){
        System.out.println("encodeName(): Method called.");
        //Name ::= CHOICE {
        //    RDNSequence }
        ArrayList<byte[]> list = new ArrayList<>();
        
        ArrayList<Integer> printable_oid = new ArrayList<>();
        printable_oid.add(85);
        printable_oid.add(4);
        printable_oid.add(3);
        
        //We add the OID then the name (already formatted)
        byte[] oid = encoder.encodeObjectIdentifier(printable_oid);
        list.add(oid);
        
        byte[] printable_string = encoder.encodePrintableString(name);
        list.add(printable_string);
        
        //Encode the AttributeTypeAndValue
        System.out.println("encodeName(): Encoding the AttributeTypeAndValue.");
        byte[] atv = encoder.encodeSEQUENCE(mProcessor.compileArrays(list));
        
        //Encode the RelativeDistinguishedName
        byte[] rdn = encoder.encodeSETOF(atv);
        
        System.out.println("encodeName(): Encoding the RDNSequence.");
        byte[] rdn_sequence = encoder.encodeSEQUENCE(rdn); //SEQUENCE OF and SEQUENCE are the same (essentially)
        
        return rdn_sequence;
    }
    
    public byte[] encodeValidity(String before, String after){
        System.out.println("encodeValidity(): Method called.");
        //Validity ::= SEQUENCE {
        //    notBefore Time,
        //    notAfter Time }
        ArrayList<byte[]> list = new ArrayList<>();
        
        byte[] bef = encoder.encodeUTCTime(before);
        list.add(bef);
        
        byte[] aft = encoder.encodeUTCTime(after);
        list.add(aft);
        
        return encoder.encodeSEQUENCE(mProcessor.compileArrays(list));
    }
    
    public byte[] encodeSubjectPublicKeyInfo(ArrayList<Integer> oid, String algorithm_name, byte[] public_key){
        System.out.println("encodeSubjectPublicKeyInfo(): Method called.");
        //SubjectPublicKeyInfo ::= SEQUENCE {
        //    algorithm AlgorithmIdentifier,
        //    subjectPublicKey BIT STRING }
        ArrayList<byte[]> list = new ArrayList<>();
        
        AlgorithmIdentifier id = new AlgorithmIdentifier();
        id.setObjectIdentifier(oid);
        id.setName(algorithm_name);
        
        byte[] ai = encodeAlgorithmIdentifier(id);
        list.add(ai);
        
        byte[] bit = encoder.encodeBitString(public_key, 0);
        list.add(bit);
        
        return encoder.encodeSEQUENCE(mProcessor.compileArrays(list));
    }
    
    public byte[] encodeAlgorithmIdentifier(X509.AlgorithmIdentifier id){
        System.out.println("encodeAlgorithmIdentifier(): Method called.");
        //SEQUENCE
        //AlgorithmIdentifier ::= SEQUENCE {
        //  algorithm   OBJECT IDENTIFIER
        //  parameters  ANY DEFINED BY algorithm OPTIONAL }
        
        //In this sequence we have an OBJECT IDENTIFIER and NULL for the params.
        ArrayList<byte[]> list = new ArrayList<>();
        //Add the OID
        byte[] oid = encoder.encodeObjectIdentifier(id.getObjectIdentifier());
        list.add(oid);
        System.out.println("encodeAlgorithmIdentifier(): Encoded the object identifier. Adding NULL params.");
        //Add the NULL params
        byte[] nll = encoder.encodeNull();
        list.add(nll);
        return encoder.encodeSEQUENCE(mProcessor.compileArrays(list));
    }
}

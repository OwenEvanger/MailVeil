/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package X509;

import ASN1.ASN1;
import ASN1.ASNDecoder;
import ASN1.ASNUtils;
import ASN1.BitString;

import CMS.ObjectIdentifier;
import java.util.ArrayList;

/**
 *
 * @author Owen
 */
public class Decoder {
    ASNDecoder mDecoder = new ASNDecoder();
    
    //CMSDecoder cmsDecoder = new CMSDecoder();
    
    ASNUtils mUtil = new ASNUtils();
    
    public Decoder(){
        
    }
    
    public CertificateList decodeCertificateList(ASN1 item){
        //CertificateList ::= SEQUENCE {
        //    tbsCertList TBSCertList,
        //    signatureAlgorithm AlgorithmIdentifier,
        //    signature BIT STRING }
        CertificateList list = new CertificateList();
        
        if(mUtil.checkSEQUENCE(item) && mUtil.size(item) == 3){
            boolean tbs = true;
            boolean alg = false;
            
            for(ASN1 inner : item.getItems()){
                if(tbs){
                    TBSCertList certs = decodeTBSCertList(inner);
                    list.setTBSCertList(certs);
                    tbs = false;
                    alg = true;
                }else if(alg){
                    AlgorithmIdentifier id = decodeAlgorithmIdentifier(inner);
                    list.setAlgorithmIdentifier(id);
                    alg = false;
                }else{
                    if(mUtil.checkBITSTRING(item) && inner.getContent() != null){
                        if(inner.isConstructed()){
                            BitString sig = mDecoder.decodeConstructedBITSTRING(inner.getItems());
                            list.setSignature(sig);
                        }else{
                            BitString sig = mDecoder.decodeBITSTRING(inner.getContent());
                            list.setSignature(sig);
                        }
                    }
                }
            }
        }
        return list;
    }
    
    public TBSCertList decodeTBSCertList(ASN1 item){
        //TBS - To be signed
        //TBSCertList ::= SEQUENCE {
        //    version Version OPTIONAL --if present, shall be v2
        //    signature AlgorithmIdentifier,
        //    issuer Name,
        //    thisUpdate Time,
        //    nextUpdate Time OPTIONAL,
        //    revokedCertificates SEQUENCE OF SEQUENCE{
        //        userCertificate CertificateSerialNumber,
        //        revocationDate Time,
        //        crlEntryExtensions Extensions OPTIONAL} OPTIONAL,
        //    crlExtensions [0] EXPLICIT Extensions OPTIONAL }
        TBSCertList list = new TBSCertList();
        if(mUtil.checkSEQUENCE(item)){
            boolean version = true;
            boolean signature = false;
            boolean issuer = false;
            boolean tu = false;
            boolean nu = false;
            boolean rc = false;
            boolean extensions = false;

            for(ASN1 inner : item.getItems()){
                if(version){
                    if(mUtil.checkINTEGER(item)){  //Must be INTEGER tag or else its the AlgorithmIdentifier
                        Version ver = decodeVersion(inner);
                        list.setVersion(ver);
                        signature = true;
                    }else{
                        AlgorithmIdentifier id = decodeAlgorithmIdentifier(inner);
                        list.setSignature(id);
                        issuer = true;
                    }
                    version = false;
                }else if(signature){
                    AlgorithmIdentifier id = decodeAlgorithmIdentifier(inner);
                    list.setSignature(id);
                    signature = false;
                    issuer = true;
                }else if(issuer){
                    Name issue = decodeName(inner);
                    list.setIssuer(issue);
                    issuer = false;
                    tu = true;
                }else if(tu){
                    Time this_update = decodeTime(inner);
                    list.setThisUpdate(this_update);
                    tu = false;
                }else{
                    if(mUtil.checkGeneralizedTime(item) || mUtil.checkUniversalTime(item)){ //CHOICE
                        //Next update
                        Time next_update = decodeTime(inner);
                        list.setNextUpdate(next_update);
                    }else if(inner.getTag() == 0){
                        if(mUtil.size(inner) == 1){
                            ASN1 internal = inner.getItems().get(0);
                            Extensions crl_extensions = decodeExtensions(internal);
                            list.setExtensions(crl_extensions);
                        }
                    }else{
                        //Revoked Certs
                        RevokedCertificates rev = decodeRevokedCertificates(inner);
                        list.setRevokedCertificates(rev);
                    }
                }
            }
        }
        return list;
    }
    
    public Certificate decodeCertificate(ASN1 item){
        //Certificate ::= SEQUENCE{ 
        //    tbsCertificate TBSCertificate,
        //    signatureAlgorithm AlgorithmIdentifier,
        //    signatureValue BIT STRING }
        System.out.println("decodeCertificate(): Method called.");
        Certificate certificate = new Certificate();
        if(mUtil.checkSEQUENCE(item)){
            boolean cert = true;
            boolean alg = false;

            for(ASN1 inner : item.getItems()){
                //NOTE: We should have three parts here.
                System.out.println("decodeCertificate(): Number of parts in Certificate structure's SEQUENCE: " + item.getItems().size());
                if(cert){
                    TBSCertificate tbs = decodeTBSCertificate(inner);
                    System.out.println("decodeCertificate(): Certificate finished.");
                    certificate.setCertificate(tbs);
                    cert = false;
                    alg = true;
                    return certificate; //Testing
                }else if(alg){
                    System.out.println("decodeCertificate(): Decoding the algorithm identifier.");
                    AlgorithmIdentifier id = decodeAlgorithmIdentifier(inner);
                    certificate.setSignatureAlgorithm(id); 
                    alg = false;
                }else{
                    System.out.println("decodeCertificate(): Decoding the bitstring.");
                    if(mUtil.checkBITSTRING(inner)){
                        if(inner.isConstructed()){
                            BitString sig = mDecoder.decodeConstructedBITSTRING(inner.getItems());
                            certificate.setSignature(sig);
                        }else{
                            BitString sig = mDecoder.decodeBITSTRING(inner.getContent());
                            certificate.setSignature(sig);
                        }
                    }
                }
            }
        }else{
            System.out.println("decodeCertificate(): Sequence identifier not found.");
        }
        return certificate;
    }
    
    public TBSCertificate decodeTBSCertificate(ASN1 item){
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
        System.out.println("decodeTBSCertificate(): Method called.");
        TBSCertificate certificate = new TBSCertificate();
        int size = mUtil.size(item);
        System.out.println("decodeTBSCertificate(): Number of items in SEQUENCE is " + size);
        if(mUtil.checkSEQUENCE(item) && (size >= 6 && size <= 10)){
            boolean version = true;
            boolean serial = false;
            boolean signature = false;
            boolean issuer = false;
            boolean validity = false;
            boolean subject = false;
            boolean info = false;
            boolean ii = false;
            boolean si = false;
            boolean extensions = false;

            for(ASN1 inner : item.getItems()){
                if(version){
                    if(inner.getTag() == 0){ //TODO: Check if context specific
                        System.out.println("decodeTBSCertificate(): EXPLICIT tag [0] for Version found.");
                        if(mUtil.size(inner) == 1){
                            ASN1 internal = inner.getItems().get(0);
                            Version vers = decodeVersion(internal);
                            certificate.setVersion(vers);
                        }
                        System.out.println("decodeTBSCertificate(): Moving from version state to serial state.");
                        serial = true;
                    }
                    //For my initial testing stop here!
                    
                    version = false;
                    //return certificate;
                }else if(serial){
                    CertificateSerialNumber csn = decodeCertificateSerialNumber(inner);
                    certificate.setCertificateSerialNumber(csn);
                    serial = false;
                    signature = true;
                    System.out.println("decodeTBSCertificate(): Moving from serial state to signature state.");
                    //return certificate;
                }else if(signature){
                    AlgorithmIdentifier alg = decodeAlgorithmIdentifier(inner);
                    certificate.setSignature(alg);
                    signature = false;
                    issuer = true;
                    System.out.println("decodeTBSCertificate(): Moving from signature state to issuer state.");
                    //return certificate;
                }else if(issuer){
                    Name issue = decodeName(inner);
                    certificate.setIssuer(issue);
                    issuer = false;
                    validity = true;
                    System.out.println("decodeTBSCertificate(): Moving from issuer state to the validity state.");
                    //return certificate;
                }else if(validity){
                    Validity valid = decodeValidity(inner);
                    certificate.setValidity(valid);
                    validity = false;
                    subject = true;
                    System.out.println("decodeTBSCertificate(): Moving from validity state to the subject state.");
                    //return certificate;
                }else if(subject){
                    Name sub = decodeName(inner);
                    certificate.setSubject(sub);
                    subject = false;
                    info = true;
                    System.out.println("decodeTBSCertificate(): Moving from subject state to info state.");
                    //return certificate;
                }else if(info){
                    SubjectPublicKeyInfo spki = decodeSubjectPublicKeyInfo(inner);
                    certificate.setSubjectPublicKeyInfo(spki);
                    info = false;
                    System.out.println("decodeTBSCertificate(): Finished with the info state.");
                    return certificate;
                }else{
                    if(inner.getTag() == 1){
                        if(mUtil.size(inner) == 1){
                            ASN1 internal = inner.getItems().get(0);
                            UniqueIdentifier ui = decodeUniqueIdentifier(internal);
                            certificate.SetIssuerId(ui);
                        }
                    }else if(inner.getTag() == 2){
                        if(mUtil.size(inner) == 1){
                            ASN1 internal = inner.getItems().get(0);
                            UniqueIdentifier ui = decodeUniqueIdentifier(internal);
                            certificate.setSubjectId(ui);
                        }
                    }else if(inner.getTag() == 3){
                        if(mUtil.size(inner) == 1){
                            ASN1 internal = inner.getItems().get(0);
                            Extensions ext = decodeExtensions(internal);
                            certificate.setExtensions(ext);
                        }
                    }
                }
            }
        }
        return certificate;
    }
    
    public Version decodeVersion(ASN1 item){
        //Version ::= INTEGER {v1(0), v2(1), v3(2)}
        System.out.println("decodeVersion(): Method called.");
        Version version = new Version();
        if(mUtil.checkINTEGER(item)){
            int ver = mDecoder.decodeINTEGER(item.getContent());
            System.out.println("decodeVersion(): Integer was found. Decoded as " + ver);
            if(ver == 0 || ver == 1 || ver == 2 || ver == 3){
                version.setVersion(++ver);
            }
        }
        return version;
    }
    
    public RevokedCertificates decodeRevokedCertificates(ASN1 item){
        //    revokedCertificates SEQUENCE OF SEQUENCE{
        //        userCertificate CertificateSerialNumber,
        //        revocationDate Time,
        //        crlEntryExtensions Extensions OPTIONAL} 
        
        RevokedCertificates rc = new RevokedCertificates();
         
        if(mUtil.checkSEQUENCEOF(item) && item.isConstructed()){ 
            for(ASN1 inner : item.getItems()){
                RevokedCertificate rev = decodeRevokedCertificate(inner);
                rc.addRevokedCertificate(rev);
            }
        }
        return rc;
    }
    
    public RevokedCertificate decodeRevokedCertificate(ASN1 item){
        //    revokedCertificates SEQUENCE OF SEQUENCE{
        //        userCertificate CertificateSerialNumber,
        //        revocationDate Time,
        //        crlEntryExtensions Extensions OPTIONAL} 
        
        RevokedCertificate rc = new RevokedCertificate();
        if(mUtil.checkSEQUENCE(item) && item.isConstructed() && (mUtil.size(item) >= 2 && mUtil.size(item) <= 3)){
            boolean cert = true;
            boolean date = false;

            for(ASN1 inner : item.getItems()){
                if(cert){
                    CertificateSerialNumber csn = decodeCertificateSerialNumber(inner);
                    rc.setCertificateSerialNumber(csn);
                    cert = false;
                    date = true;
                }else if(date){
                    Time rd = decodeTime(inner);
                    rc.setRevocationTime(rd);
                    date = false;
                }else{
                    Extensions ext = decodeExtensions(inner);
                    rc.setExtensions(ext);
                }
            }
        }
        return rc;
    }
    
    public CertificateSerialNumber decodeCertificateSerialNumber(ASN1 item){
        //CertificateSerialNumber ::= INTEGER
        System.out.println("decodeCertificateSerialNumber(): Method called.");
        CertificateSerialNumber csn = new CertificateSerialNumber();
        csn.setSerialBytes(item.getContent());
        if(mUtil.checkINTEGER(item)){
            int serial = mDecoder.decodeINTEGER(item.getContent());
            csn.setSerialNumber(serial);
            System.out.println("decodeCertificateSerialNumber(): Serial number is " + serial);
        }
        return csn;
    }
    
    public Validity decodeValidity(ASN1 item){
        //Validity ::= SEQUENCE {
        //    notBefore Time,
        //    notAfter Time }
        System.out.println("decodeValidity(): Method called.");
        Validity valid = new Validity();
        if(mUtil.checkSEQUENCE(item) && mUtil.size(item) == 2){
            boolean before = true;

            for(ASN1 inner : item.getItems()){
                if(before){
                    Time nb = decodeTime(inner);
                    valid.setNotBefore(nb);
                    before = false;
                }else{
                    Time na = decodeTime(inner);
                    valid.setNotAfter(na);
                }
            }
        }
        return valid;
    }
    
    public Time decodeTime(ASN1 item){
        //Time ::= CHOICE {
        //    utcTime UTCTime,
        //    generalTime GeneralizedTime }
        System.out.println("decodeTime(): Method called.");
        Time t = new Time();
        if(true){
            if(mUtil.checkUniversalTime(item)){  //Universal time
                System.out.println("decodeTime(): Decoding UTC time.");
                String time = mDecoder.decodeUniversalTime(item);
                //TODO: Universal and Generalized time are IMPLICIT...
                //String time = new String(item.getContent());
                t.setUTCTime(time);
            }else if(mUtil.checkGeneralizedTime(item)){
                System.out.println("decodeTime(): Decoding Generalized time.");
                String time = mDecoder.decodeGeneralizedTime(item);
                t.setGeneralizedTime(time);
            }
        }
        return t;
    }
    
    public UniqueIdentifier decodeUniqueIdentifier(ASN1 item){
        //UniqueIdentifier ::= BIT STRING
        UniqueIdentifier ui = new UniqueIdentifier();
        if(mUtil.checkBITSTRING(item)){
            if(item.isConstructed()){
                BitString id = mDecoder.decodeConstructedBITSTRING(item.getItems());
                ui.setUniqueIdentifier(id);
            }else{
                BitString id = mDecoder.decodeBITSTRING(item.getContent());
                ui.setUniqueIdentifier(id);
            }
        }
        return ui;
    }
    
    public SubjectPublicKeyInfo decodeSubjectPublicKeyInfo(ASN1 item){
        //SubjectPublicKeyInfo ::= SEQUENCE {
        //    algorithm AlgorithmIdentifier,
        //    subjectPublicKey BIT STRING }
        System.out.println("decodeSubjectPublicKeyInfo(): Method called.");
        SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo();
        if(mUtil.checkSEQUENCE(item) && mUtil.size(item) == 2){
            boolean alg = true;

            for(ASN1 inner : item.getItems()){
                if(alg){
                    AlgorithmIdentifier id = decodeAlgorithmIdentifier(inner);
                    spki.setAlgorithmIdentifier(id);
                    alg = false;
                }else{
                    System.out.println("decodeSubjectPublicKeyInfo(): Working on the Bit String.");
                    if(inner.isConstructed()){
                        BitString key = mDecoder.decodeConstructedBITSTRING(inner.getItems());
                        spki.setSubjectPublicKey(key);
                    }else{
                        BitString key = mDecoder.decodeBITSTRING(inner.getContent());
                        spki.setSubjectPublicKey(key);
                    }
                }
            }
        }
        return spki;
    }
    
    public Extensions decodeExtensions(ASN1 item){
        //Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension
        Extensions extensions = new Extensions();
        if(mUtil.checkSEQUENCE(item) && mUtil.size(item) >= 1){
            for(ASN1 inner : item.getItems()){
                Extension extension = decodeExtension(inner);
                extensions.addToExtensions(extension);
            }
        }
        return extensions;
    }
    
    public Extension decodeExtension(ASN1 item){
        //Extension ::= SEQUENCE {
        //    extnID OBJECT IDENTIFIER,
        //    critical BOOLEAN DEFAULT FALSE,
        //    extnValue OCTET STRING }
        Extension extension = new Extension();
        if(mUtil.checkSEQUENCE(item) && mUtil.size(item) == 3){
            boolean id = true;
            boolean critical = false;
            boolean val = false;

            for(ASN1 inner : item.getItems()){
                if(id){
                    ObjectIdentifier identifier = new ObjectIdentifier();
                    if(mUtil.checkOBJECTIDENTIFIER(inner)){
                        ArrayList<Integer> ids = mDecoder.decodeObjectIdentiferToSubIds(inner.getContent());
                        identifier.setObjectIdentifier(ids);
                    }
                    extension.setObjectIdentifier(identifier);
                    id = false;
                    critical = true;
                }else if(critical){
                    if(mUtil.checkBOOLEAN(item)){
                        boolean crit = mDecoder.decodeBOOLEAN(inner.getContent());
                        if(crit){
                            extension.setCritical();
                        }
                    }
                    critical = false;
                    val = true;
                }else if(val){
                    if(mUtil.checkOCTETSTRING(item)){
                        byte[] value = mDecoder.decodeOCTETSTRING(inner.getContent());
                        extension.setExtensionValue(value);
                    }
                }
            }
        }
        return extension;
    }
    
    public Name decodeName(ASN1 item){
        //Name ::= CHOICE {
        //    RDNSequence }   
        System.out.println("decodeName(): Method called.");
        Name name = new Name();
        if(mUtil.size(item) > 0){
            System.out.println("decodeName(): Decoding the RDNSequence.");
            RDNSequence sequence = decodeRDNSequence(item);
            name.setRDNSequence(sequence);
        }
        return name;
    }
    
    public RDNSequence decodeRDNSequence(ASN1 item){
        //RDNSequence ::= SEQUENCE OF RelativeDistinguisedName
        System.out.println("decodeRDNSequence(): Method called.");
        RDNSequence sequence = new RDNSequence();
        if(mUtil.checkSEQUENCEOF(item)){
            for(ASN1 inner : item.getItems()){
                RelativeDistinguishedName name = decodeRelativeDistinguishedName(inner);
                sequence.addRelativeDistinguishedName(name);
            }
        }
        return sequence;
    }
    
    public RelativeDistinguishedName decodeRelativeDistinguishedName(ASN1 item){
        //RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
        System.out.println("decodeRelativeDistinguishedName(): Method called.");
        RelativeDistinguishedName rdn = new RelativeDistinguishedName();
        if(mUtil.checkSET(item)){
            for(ASN1 inner : item.getItems()){
                AttributeTypeAndValue atav = decodeAttributeTypeAndValue(inner);
                rdn.addAttributeTypeAndValue(atav);
            }
        }
        return rdn;
    }
    
    public AttributeTypeAndValue decodeAttributeTypeAndValue(ASN1 item){
        //AttributeTypeAndValue ::= SEQUENCE {
        //    type AttributeType,
        //    value AttributeValue }
        System.out.println("decodeAttributeTypeAndValue(): Method called.");
        AttributeTypeAndValue atav = new AttributeTypeAndValue();
        if(mUtil.checkSEQUENCE(item) && mUtil.size(item) == 2){
            boolean type = true;

            for(ASN1 a : item.getItems()){
                if(type){
                    System.out.println("decodeAttributeTypeAndValue(): Decoding the type.");
                    AttributeType at = decodeAttributeType(a);
                    atav.setAttributeType(at);
                    type = false;
                }else{
                    System.out.println("decodeAttributeTypeAndValue(): Decoding the value.");
                    AttributeValue av = decodeAttributeValue(a);
                    atav.setAttributeValue(av);
                }
            }
        }
        return atav;
    }
    
    public AttributeType decodeAttributeType(ASN1 item){
        //AttributeType ::= OBJECT IDENTIFIER
        System.out.println("decodeAttributeType(): Method called.");
        AttributeType type = new AttributeType();
        ObjectIdentifier identifier = new ObjectIdentifier();
        if(mUtil.checkOBJECTIDENTIFIER(item)){
            ArrayList<Integer> list = mDecoder.decodeObjectIdentiferToSubIds(item.getContent());
            identifier.setObjectIdentifier(list);
        }
        type.setObjectIdentifier(identifier);
        return type;
    }
    
    public AttributeValue decodeAttributeValue(ASN1 item){
        //AttributeValue ::= ANY DEFINED BY AttributeType
        System.out.println("decodeAttributeValue(): Method called.");
        AttributeValue value = new AttributeValue();
        //We need to know the type to validate this
        value.setAttributeValue(item);
        return value;
    }
    
    public RSAPublicKey decodeRSAPublicKey(ASN1 item){
        //RSAPublicKey ::= SEQUENCE {
        //    modulus INTEGER,  --n
        //    publicExponent INTEGER --e--}
        RSAPublicKey key = new RSAPublicKey();
        if(mUtil.checkSEQUENCE(item) && mUtil.size(item) == 2){        
            boolean mod = true;

            for(ASN1 r : item.getItems()){
                if(mUtil.checkINTEGER(r)){              
                    if(mod){
                        int modulus = mDecoder.decodeINTEGER(r.getContent());
                        key.setModulus(modulus);
                        mod = false;
                    }else{
                        int exponent = mDecoder.decodeINTEGER(r.getContent());
                        key.setPublicExponent(exponent);
                    }
                }
            }
        }
        return key;
    }
    
    public AlgorithmIdentifier decodeAlgorithmIdentifier(ASN1 asn){
        //AlgorithmIdentifier ::= SEQUENCE{
        //    algorithm      OBJECT IDENTIFIER
        //    params         ANY DEFINED BY algorithm OPTIONAL}
        System.out.println("decodeAlgorithmIdentifier(): Method called.");
        boolean oi = true;
        
        AlgorithmIdentifier alg_id = new AlgorithmIdentifier();
        int size = mUtil.size(asn);
        if(mUtil.checkSEQUENCE(asn) && (size == 1 || size == 2)){
            System.out.println("decodeAlgorithmIdentifier(): Iterating through child items.");
            for(ASN1 alg : asn.getItems()){
                //First we have the object id
                if(oi){
                    System.out.println("decodeAlgorithmIdentifier(): Decoding the sub ids.");
                    //Get the list of sub ids
                    ArrayList<Integer> subIDs = mDecoder.decodeObjectIdentiferToSubIds(alg.getContent());
                    alg_id.setObjectIdentifier(subIDs);
                    oi = false;
                }else{
                    //On params
                    if(alg.getTag() != 5){  //Ignore NULL
                        byte[] params = alg.getContent();
                        alg_id.setParams(params);
                    }else{
                        System.out.println("decodeAlgorithmIdentifier(): Avoiding the NULL object.");
                    }
                }
            }
        }
        return alg_id;
    }
}

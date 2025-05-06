/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package CMS;

import ASN1.ASN1;
import ASN1.ASNDecoder;
import ASN1.ASNUtils;
import ASN1.BitString;
import X509.Decoder;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Stack;

/**
 *
 * @author Owen
 */
public class CMSDecoder {
    public ASNDecoder mDecoder = new ASNDecoder();
    
    ASNUtils mUtil = new ASNUtils();
    
    //Decoder xDecoder = new Decoder();
    
    public CMSDecoder(){
        
    }
    
    /** decodeContentInfo() decodes the encoded bytes into a ContentInfo object.
     * 
     * @param bytes The encoded bytes
     * @return ContentInfo object
     * @since 1.0
     */
    public ContentInfo decodeContentInfo(byte[] bytes){
        System.out.println("decodeContentInfo(): Method called.");
        //Content-Info ::= SEQUENCE {
        //    contentType ContentType,
        //    content [0] EXPLICIT ANY DEFINED BY contentType }
        
        //First we parse the bytes into the various ASN1 structures
        ASN1 asn = mDecoder.genericDecode(bytes);
        System.out.println("decodeContentInfo(): Content Info decoded.");
        ContentInfo ci = new ContentInfo();
        ci.setContents(asn);
        
        boolean type = true;
        
        //We ensure that we have 2 objects and that the SEQUENCE is their parent.
        if(mUtil.checkSEQUENCE(asn) && mUtil.size(asn) == 2){      
            for(ASN1 item : asn.getItems()){
                if(type){
                    ContentType ct = new ContentType();
                    //We expect an OID
                    if(mUtil.checkOBJECTIDENTIFIER(item)){
                        System.out.println("decodeContentInfo(): Decoding the OID.");
                        ct.setContentType(mDecoder.decodeObjectIdentiferToSubIds(item.getContent()));
                        type = false;
                    }else{
                        System.out.println("decodeContentInfo(): OID not found");
                        return null;
                    }
                }else{
                    //We expect the explicit tag 0
                    if(item.getTagNumber() == 0){
                        //Size should be 1
                        if(mUtil.size(item) == 1){
                            if(item.getContent() == null){
                                System.out.println("We have a null array.");
                                return null;
                            }
                            ASN1 inner = item.getItems().get(0);
                            //System.out.println("Tag is " + inner.getTagNumber());
                            //We add the encoded content.
                            ci.setContent(item.getContent());
                            System.out.println("decodeContentInfo(): Content was isolated.");
                        }else{
                            System.out.println("decodeContentInfo(): Nothing deeper than the EXPLICIT [0] tag.");
                            return null;
                        }
                    }else{
                        System.out.println("decodeContentInfo(): EXPLICIT [0] not found.");
                        return null;
                    }
                }
            }
        }else{
            System.out.println("decodeContentInfo(): Parsing error.");
            //Error
            return null;
        }
        return ci;
    }
    
    /** decodeSignedData() decoded the encoded bytes into the SignedData object.
     * 
     * NOTE: certificates and crls have not been tested yet
     * 
     * @param ci A ContentInfo object with either the raw encoded bytes and/or the decoded high level ASN1 object.
     * @return The SignedData object 
     * @since 1.0
     */
    public SignedData decodeSignedData(ContentInfo ci){
        System.out.println("decodeSignedData(): Method called.");
        /* SignedData ::= SEQUENCE {
        **    version           CMSVersion,
        **    digestAlgorithms  DigestAlgorithmIdentifiers,
        **    encapContentInfo  EncapsulatedContentInfo,
        **    certificates [0] IMPLICIT CertificateSet OPTIONAL,
        **    crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
        **    signerInfos SignerInfos }
        */
        SignedData signed_data = new SignedData();
        
        boolean version = true;
        boolean digest_algs = false;
        boolean encap_content_info = false;
        boolean optional = false;
        
        //First we parse the bytes into the various ASN1 structures if necessary.
        ASN1 asn;
        if(ci.getContent() != null){
            asn = mDecoder.genericDecode(ci.getContent());
        }else{
            asn = ci.getContents();
        }
        
        System.out.println("decodeSignedData(): Decoding finised.");
        //Our specification above allows us to move through the ASN1 tree and get each value
        //The first ASN1 tag must be a SEQUENCE tag
        
        if(mUtil.checkSEQUENCE(asn)){
            //Start our main level iteration
            for(ASN1 item : asn.getItems()){
                if(version){
                    //RFC 3852 p.38
                    //CMSVersion ::= INTEGER {v0(0), v1(1), v2(2), v3(3), v4(4), v5(5)}
                    //We do not have depth so we can grab the integer

                    //Decode the INTEGER into the version number
                    if(mUtil.checkINTEGER(item)){
                        int ver = mDecoder.decodeINTEGER(item.getContent());
                        signed_data.setCMSVersion(ver);
                        System.out.println("decodeSignedData(): Version is " + ver);
                    }else{
                        System.out.println("decodeSignedData(): INTEGER was not found in version.");
                        return null;
                    }
                    version = false;
                    digest_algs = true;
                }else if(digest_algs){
                    //DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
                    //DigestAlgorithmIdentifier ::= AlgorithmIdentifier
                    //AlgorithmIdentifier ::= SEQUENCE{
                    //    algorithm      OBJECT IDENTIFIER
                    //    params         ANY DEFINED BY algorithm OPTIONAL}
                    boolean oi = true;
                    //Tag should be SET OF
                    if(mUtil.checkSETOF(item)){
                        //Iterate through the set
                        for(ASN1 digestID : item.getItems()){
                            //We have an Algorithm id, whose tag should be SEQUENCE
                            AlgorithmIdentifier alg_id = decodeAlgorithmIdentifier(digestID);
                            if(alg_id == null){
                                System.out.println("decodeSignedData(): AlgorithmIdentifier was null for digest algs.");
                                return null;
                            }
                            signed_data.addDigestAlgorithmID(alg_id);
                        }
                    }else{
                        System.out.println("decodeSignedData(): SET OF was expected for algorithm identifiers.");
                        return null;
                    }
                    digest_algs = false;
                    encap_content_info = true;
                }else if(encap_content_info){
                    //EncapsulatedContentInfo ::= SEQUENCE {
                    //    eContentType   ContentType,
                    //    eContent[0] EXPLICIT OCTET STRING OPTIONAL}
                    EncapsulatedContentInfo in = decodeEncapsulatedContentInfo(item);
                    if(in == null){
                        System.out.println("decodeSignedData(): EncapsulatedContentInfo was null.");
                        return null;
                    }
                    byte[] cnt = in.getContent();
                    System.out.println("decodeSignedData(): Encapsulated content: " + new String(cnt));
                    signed_data.setEncapsulatedContentInfo(in);

                    encap_content_info = false;
                    optional = true;
                }else if(optional){
                    //Check the tag to see which optional item we are on
                    //TODO:
                    if(item.getTag() == 0){
                        //CertificateSet ::= SET OF CertificateChoices
                        if(mUtil.size(item) == 1){
                            ASN1 next = item.getItems().get(0);
                            //Check for SET
                            CertificateSet certs = decodeCertificateSet(next);
                            signed_data.addCertificateSet(certs);
                        }
                    }else if(item.getTag() == 1){
                        //Check for SET
                        if(mUtil.checkSET(item)){
                            for(ASN1 it : item.getItems()){
                                RevocationInfoChoice ch = decodeRevocationInfoChoice(it);
                                signed_data.addRevocationInfoChoice(ch);
                            }
                        }else{
                            System.out.println("decodeSignedData(): SET was expected for CRLs.");
                            return null;
                        }
                    }else{
                        //We have SignerInfos
                        //Check for SET OF
                        if(mUtil.checkSETOF(item)){
                            for(ASN1 info : item.getItems()){
                                System.out.println("decodeSignedData(): Decoding the signer info.");
                                SignerInfo si = decodeSignerInfo(info);
                                if(si == null){
                                    System.out.println("decodeSignedData(): SignerInfo returned null.");
                                    return null;
                                }
                                signed_data.addSignerInfo(si);
                            }
                        }else{
                            System.out.println("decodeSignedData(): SET OF not found in SignerInfos.");
                            return null;
                        }
                    }
                }
            }
        }else{
            return null;
        }
        return signed_data;
    }
    
    
    
    public EnvelopedData decodeEnvelopedData(ASN1 data){
        //EnvelopedData ::= SEQUENCE {
        //    version CMSVersion,
        //    originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
        //    recipientInfos RecipientInfos,
        //    encryptedContentInfo EncryptedContentInfo,
        //    unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
        EnvelopedData ed = new EnvelopedData();
        int size = mUtil.size(data);
        if(mUtil.checkSEQUENCE(data) && (size >= 3 && size <= 5)){
            boolean version = true;
            boolean optional = false;
            boolean recip = false;
            boolean encryp = false;


            for(ASN1 item : data.getItems()){
                if(version){
                    int vers = mDecoder.decodeINTEGER(item.getContent());
                    ed.setCMSVersion(vers);
                    version = false;
                    optional = true;
                }else if(optional){
                    if(item.getTag() == 0 && mUtil.size(item) == 1){
                        ASN1 inner = item.getItems().get(0);
                        OriginatorInfo info = decodeOriginatorInfo(inner);
                        ed.setOriginatorInfo(info);
                        recip = true;
                    }else if(item.getTag() == 1 && mUtil.size(item) == 1){
                        ASN1 inner = item.getItems().get(0);
                        UnprotectedAttributes ua = decodeUnprotectedAttributes(inner);
                        ed.setUnprotectedAttributes(ua);
                    }else{
                        RecipientInfos ris = decodeRecipientInfos(item);
                        ed.setRecipientInfos(ris);
                    }
                    optional = false;
                }else if(recip){
                    RecipientInfos ris = decodeRecipientInfos(item);
                    ed.setRecipientInfos(ris);
                    recip = false;
                    encryp = true;
                }else if(encryp){
                    EncryptedContentInfo eci = decodeEncryptedContentInfo(item);
                    ed.setEncryptedContentInfo(eci);
                    encryp = false;
                    optional = true;
                }
            }
        }
        return ed;
    }
    
    public DigestedData decodeDigestedData(ASN1 item){
        //DigestedData ::= SEQUENCE {
        //    version CMSVersion,
        //    digestAlgorithm DigestAlgorithmIdentifier,
        //    encapContentInfo EncapsulatedContentInfo,
        //    digest Digest }
        DigestedData dat = new DigestedData();
        if(mUtil.checkSEQUENCE(item) && mUtil.size(item) == 4){
            boolean version = true;
            boolean alg = false;
            boolean info = false;
            boolean digest = false;

            for(ASN1 data : item.getItems()){
                if(version){
                    if(mUtil.checkINTEGER(data)){
                        int ver = mDecoder.decodeINTEGER(data.getContent());
                        dat.setCMSVersion(ver);
                    }
                    version = false;
                    alg = true;
                }else if(alg){
                    DigestAlgorithmIdentifier dai = new DigestAlgorithmIdentifier();
                    AlgorithmIdentifier ai = decodeAlgorithmIdentifier(data);
                    dai.setAlgorithmIdentifier(ai);
                    dat.setDigestAlgorithmIdentifier(dai);
                    alg = false;
                    info = true;
                }else if(info){
                    EncapsulatedContentInfo eci = decodeEncapsulatedContentInfo(data);
                    if(eci == null){
                        
                    }
                    dat.setEncapsulatedContentInfo(eci);
                    info = false;
                    digest = true;
                }else if(digest){
                    if(mUtil.checkOCTETSTRING(data)){
                        byte[] dig = mDecoder.decodeOCTETSTRING(data.getContent());
                        dat.setDigest(dig);
                    }
                }
            }
        }
        return dat;
    }
    
    /** decodeEncryptedData() decodes the ContentInfo object into an EncryptedData object.
     * 
     * @param ci
     * @return The EncryptedData object
     * @since 1.0
     */
    public EncryptedData decodeEncryptedData(ContentInfo ci){
        System.out.println("decodeEncryptedData(): ");
        //EncryptedData ::= SEQUENCE {
        //    version CMSVersion,
        //    encryptedContentInfo EncryptedContentInfo,
        //    unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL}
        ASN1 item;
        if(ci.getContent() != null){
            item = mDecoder.genericDecode(ci.getContent());
        }else{
            item = ci.getContents();
        }
        
        System.out.println("decodeEncryptedData(): Generic decoding finished.");
        EncryptedData ed = new EncryptedData();
        int size = mUtil.size(item);
        if(mUtil.checkSEQUENCE(item) && (size == 2 || size == 3)){
            boolean version = true;
            boolean info = false;

            for(ASN1 data : item.getItems()){
                if(version){
                    if(mUtil.checkINTEGER(data)){
                        int ver = mDecoder.decodeINTEGER(data.getContent());
                        ed.setCMSVersion(ver);
                    }else{
                        System.out.println("decodeEncryptedData(): CMSVersion was not an integer.");
                        return null;
                    }
                    System.out.println("decodeEncryptedData(): CMSVersion complete.");
                    version = false;
                    info = true;
                }else if(info){
                    System.out.println("decodeEncryptedData(): Working on EncryptedContentInfo.");
                    EncryptedContentInfo eci = decodeEncryptedContentInfo(data);
                    if(eci == null){
                        System.out.println("decodeEncryptedData(): ");
                        return null;
                    }
                    ed.setEncryptedContentInfo(eci);
                    info = false;
                }else{
                    if(data.getTag() == 1){
                        //IMPLICIT
                        //ASN1 inner = data.getItems().get(0);
                        UnprotectedAttributes uas = decodeUnprotectedAttributes(data);
                        ed.setUnprotectedAttributes(uas);
                        return ed;
                    }else{
                        System.out.println("decodeEncryptedData(): Poorly formed UnprotectedAttributes.");
                        //Poorly formed
                        return null;
                    }
                }
            }
        }else{
            System.out.println("decodeEncryptedData(): SEQUENCE was expected.");
            return null;
        }
        return ed;
    }
    
    public AuthenticatedData decodeAuthenticatedData(ASN1 item){
        //AuthenticatedData ::= SEQUENCE {
        //    version CMSVersion,
        //    originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
        //    recipientInfos RecipientInfos,
        //    macAlgorithm MessageAuthenticationCodeAlgorithm,
        //    digestAlgorithm [1] DigestAlgorithmIdentifier OPTIONAL,
        //    encapContentInfo EncapsulatedContentInfo,
        //    authAttrs [2] IMPLICIT AuthAttributes OPTIONAL,
        //    mac MessageAuthenticationCode,
        //    unauthAttrs [3] IMPLICIT UnauthAttributes OPTIONAL }
        AuthenticatedData authenticated = new AuthenticatedData();
        int size = mUtil.size(item);
        if(mUtil.checkSEQUENCE(item) && (size >= 5 && size <= 9)){
            boolean version = true;
            boolean orig = false;
            boolean recip = false;
            boolean malg = false;
            boolean dalg = false;
            boolean cinfo = false;
            boolean aa = false;
            boolean mac = false;
            boolean ua = false;

            for(ASN1 dat : item.getItems()){
                if(version){
                    if(mUtil.checkINTEGER(dat)){
                        int vers = mDecoder.decodeINTEGER(dat.getContent());
                        authenticated.setCMSVersion(vers);
                    }
                    version = false;
                    orig = true;
                }else if(orig){
                    if(dat.getTag() == 0){
                        if(mUtil.size(dat) == 1){
                            ASN1 inner = dat.getItems().get(0);
                            OriginatorInfo orignator_info = decodeOriginatorInfo(inner);
                            authenticated.setOriginatorInfo(orignator_info);
                        }
                        recip = true;
                    }else{
                        RecipientInfos infos = decodeRecipientInfos(dat);
                        authenticated.setRecipientInfos(infos);
                        malg = true;
                    }
                    orig = false;
                }else if(recip){
                    RecipientInfos infos = decodeRecipientInfos(dat);
                    authenticated.setRecipientInfos(infos);
                    recip = false;
                    malg = true;
                }else if(malg){
                    AlgorithmIdentifier identifier = decodeAlgorithmIdentifier(dat);
                    MessageAuthenticationCodeAlgorithm mac_alg = new MessageAuthenticationCodeAlgorithm();
                    mac_alg.setAlgorithmIdentifier(identifier);
                    authenticated.setMessageAuthenticationCodeAlgorithm(mac_alg);
                    malg = false;
                    dalg = true;
                }else if(dalg){
                    if(dat.getTag() == 1){
                        if(mUtil.size(dat) == 1){
                            ASN1 inner = dat.getItems().get(0);
                            AlgorithmIdentifier identifier = decodeAlgorithmIdentifier(inner);
                            DigestAlgorithmIdentifier digest_alg = new DigestAlgorithmIdentifier();
                            digest_alg.setAlgorithmIdentifier(identifier);
                            authenticated.setDigestAlgorithmIdentifier(digest_alg);
                        }
                        cinfo = true;
                    }else{
                        EncapsulatedContentInfo encap_info = decodeEncapsulatedContentInfo(dat);
                        authenticated.setEncapsulatedContentInfo(encap_info);
                        aa = true;
                    }
                    dalg = false;
                }else if(cinfo){
                    EncapsulatedContentInfo encap_info = decodeEncapsulatedContentInfo(dat);
                    authenticated.setEncapsulatedContentInfo(encap_info);
                    cinfo = false;
                    aa = true;
                }else if(aa){
                    if(dat.getTag() == 2){
                        if(mUtil.size(dat) == 1){
                            ASN1 inner = dat.getItems().get(0);
                            AuthAttributes auth = decodeAuthAttributes(inner);
                            authenticated.setAuthAttributes(auth);
                        }
                        mac = true;
                    }else{
                        MessageAuthenticationCode message_code = decodeMessageAuthenticationCode(dat);
                        authenticated.setMessageAuthenticationCode(message_code);
                        ua = true;
                    }
                    aa = false;
                }else if(mac){
                    MessageAuthenticationCode message_code = decodeMessageAuthenticationCode(dat);
                    authenticated.setMessageAuthenticationCode(message_code);
                    mac = false;
                    ua = true;
                }else if(ua){
                    if(dat.getTag() == 3){
                        if(mUtil.size(dat) == 1){
                            ASN1 inner = dat.getItems().get(0);
                            UnauthAttributes unauth_attributes = decodeUnauthAttributes(inner);
                            authenticated.setUnauthAttributes(unauth_attributes);
                        }
                    }
                }
            }
        }
        return authenticated;
    }
    
    public MessageAuthenticationCode decodeMessageAuthenticationCode(ASN1 item){
        //MessageAuthenticationCode ::= OCTET STRING 
        MessageAuthenticationCode mac = new MessageAuthenticationCode();
        if(mUtil.checkOCTETSTRING(item)){
            byte[] code = mDecoder.decodeOCTETSTRING(item.getContent());
            mac.setMessageAuthenticationCode(code);
        }
        return mac;
    }
    
    public UnauthAttributes decodeUnauthAttributes(ASN1 item){
        //UnauthAttributes ::= SET SIZE (1..MAX) OF Attribute
        UnauthAttributes attrs = new UnauthAttributes();
        if(mUtil.checkSET(item) && mUtil.size(item) >= 1){
            for(ASN1 attr: item.getItems()){
                Attribute attribute = decodeAttribute(attr);
                attrs.addAttribute(attribute);
            }
        }
        return attrs;
    }
    
    public AuthAttributes decodeAuthAttributes(ASN1 item){
        //AuthAttributes ::= SET SIZE (1..MAX) OF Attribute
        AuthAttributes attrs = new AuthAttributes();
        if(mUtil.checkSET(item) && mUtil.size(item) >= 1){
            for(ASN1 attr: item.getItems()){
                Attribute attribute = decodeAttribute(attr);
                attrs.addAttribute(attribute);
            }
        }
        return attrs;
    }
    
    /** decodeEncapsulatedContentInfo() decodes the ASN1 object into an EncodedContentInfo object.
     * 
     * @param item The ASN1 object
     * @return An EncapsulatedContentInfo object
     * @since 1.0
     */
    public EncapsulatedContentInfo decodeEncapsulatedContentInfo(ASN1 item){
        System.out.println("decodeEncapsulatedContentInfo(): Method called.");
        //EncapsulatedContentInfo ::= SEQUENCE {
        //    eContentType ContentType,
        //    eContent [0] EXPLICIT OCTET STRING OPTIONAL }
        EncapsulatedContentInfo eci = new EncapsulatedContentInfo();
        int size = mUtil.size(item);
        if(mUtil.checkSEQUENCE(item) && (size == 1 || size == 2)){
            for(ASN1 info : item.getItems()){
                if(info.getTag() == 0){
                    if(mUtil.size(info) == 1){
                        ASN1 inner = info.getItems().get(0);
                        if(mUtil.checkOCTETSTRING(inner)){
                            System.out.println("decodeEncapsulatedContentInfo(): Octetstring checked.");
                            byte[] content = mDecoder.decodeOCTETSTRING(inner.getContent());
                            eci.setContent(content);
                        }else{
                            System.out.println("decodeEncapsulatedContentInfo(): Octetstring was expected for eContent.");
                            return null;
                        }
                    }else{
                        System.out.println("decodeEncapsulatedContentInfo(): Improper size for eContent.");
                        return null;
                    }
                }else{
                    ContentType type = new ContentType();
                    if(mUtil.checkOBJECTIDENTIFIER(info)){
                        ArrayList<Integer> ids = mDecoder.decodeObjectIdentiferToSubIds(info.getContent());
                        type.setContentType(ids);
                    }else{
                        System.out.println("decodeEncapsulatedContentInfo(): OBJECTIDENTIFIER was not found.");
                        return null;
                    }
                    eci.setContentType(type);
                }
            }
        }else{
            System.out.println("decodeEncapsulatedContentInfo(): SEQUENCE and/or proper size not found.");
            return null;
        }
        return eci;
    }
    
    public CertificateSet decodeCertificateSet(ASN1 item){
        //CertificateSet ::= SET OF CertificateChoices
        //Check for SET
        CertificateSet certs = new CertificateSet();
        if(mUtil.checkSETOF(item)){
            for(ASN1 set : item.getItems()){
                //CertificateChoices ::= CHOICE {
                //    certificate Certificate,
                //    extendedCertificate [0] IMPLICIT ExtendedCertificate,
                //    v1AttrCert [1] IMPLICIT AttributeCertificateV1,
                //    v2AttrCert [2] IMPLICIT AttributeCertificateV2,
                //    other [3] IMPLICIT OtherCertificateFormat }
                Certificate cert = new Certificate();
                //Check CHOICE
                if(set.getTag() == 0){
                    if(mUtil.size(set) == 1){
                        cert.addExtended(set.getItems().get(0).getContent());
                    }
                }else if(set.getTag() == 1){
                    if(mUtil.size(set) == 1){
                        cert.addV1AttrCert(set.getItems().get(0).getContent());
                    }    
                }else if(set.getTag() == 2){
                    if(mUtil.size(set) == 1){
                        cert.addV2AttrCert(set.getItems().get(0).getContent());
                    }    
                }else if(set.getTag() == 3){
                    if(mUtil.size(set) == 1){
                        cert.addOther(set.getItems().get(0).getContent());
                    }
                }else{
                    //Regular X509 cert
                    cert.addX509(set.getContent());
                }
                certs.addCert(cert);
            }
        }
        return certs;
    }
    
    public RevocationInfoChoice decodeRevocationInfoChoice(ASN1 item){
        //Check for SET OF
        RevocationInfoChoice ric = new RevocationInfoChoice();
        if(mUtil.checkSETOF(item)){
            for(ASN1 choice : item.getItems()){
                //RevocationInfoChoice ::= CHOICE {
                //    crl CertificateList,
                //    other [1] IMPLICIT OtherRevocationInfoFormat}
                if(mUtil.size(choice) == 1){
                    boolean cert = true;
                    for(ASN1 ch : choice.getItems()){
                        if(cert){
                            //Decode the CertificateList
                            
                            //TEST!!!
                            //X509.CertificateList list = xDecoder.decodeCertificateList(ch);
                            //ric.addCertificateList(list);
                            cert = false;
                        }else{
                            if(ch.getTag() == 1){
                                ric.addOther(ch.getContent());
                            }else{
                                //error
                            }
                        }
                    }
                }
            }
        }
        return ric;
    }
    
    /** decodeSignerInfo() decodes the ASN1 object into a SignerInfo object.
     * 
     * NOTE: The signed and unsigned attributes have not been tested.
     * 
     * @param info The ASN1 object
     * @return A SignerInfo object, or null if the decoding fails
     * @since 1.0
     */
    public SignerInfo decodeSignerInfo(ASN1 info){
        System.out.println("decodeSignerInfo(): Method called.");
        //SignerInfo ::= SEQUENCE{
        //    version CMSVersion,
        //    sid SignerIdentifier,
        //    digestAlgorithm DigestAlgorithmIdentifier,
        //    signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
        //    signatureAlgorithm SignatureAlgorithmIdentifier,
        //    signature SignatureValue,
        //    unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
        
        SignerInfo signer_info = new SignerInfo();
        if(mUtil.checkSEQUENCE(info)){
            boolean cmsversion = true;
            boolean signer_id = false;
            boolean digest_id = false;
            boolean optional = false;
            boolean signature_id = false;
            boolean signature_state = false;

            for(ASN1 item : info.getItems()){
                if(cmsversion){
                    if(mUtil.checkINTEGER(item)){
                        int version = decodeCMSVersion(item);
                        signer_info.setCMSVersion(version);
                    }else{
                        System.out.println("decodeSignerInfo(): INTEGER not found in cms version.");
                        return null;
                    }
                    cmsversion = false;
                    signer_id = true;
                }else if(signer_id){
                    //Check if tag is CHOICE, size ==1
                    SignerIdentifier id = new SignerIdentifier();
                    
                    if(item.getTag() == 0 && mUtil.size(item) > 0){
                        System.out.println("decodeSignerInfo(): Decoding the signer ids subject key identifier.");
                        //SubjectKeyIdentifier ::= OCTET STRING
                        ASN1 inner = item.getItems().get(0);
                        //Decode the octet string
                        byte[] sid = mDecoder.decodeOCTETSTRING(inner.getContent());
                        id.setSubjectKeyIdentifier(sid);
                    }else{
                        //Check if SEQUENCE
                        if(mUtil.checkSEQUENCE(item)){
                            IssuerAndSerialNumber issue = new IssuerAndSerialNumber();
                            boolean name = true;
                            for(ASN1 isn : item.getItems()){
                                if(name){
                                    issue.setName(isn);
                                    name = false;
                                }else{
                                    //CertificateSerialNumber ::= INTEGER
                                    int csn = mDecoder.decodeINTEGER(isn.getContent());
                                    issue.setSerialNumber(csn);
                                }
                            }
                            id.setISN(issue);
                        }else{
                            System.out.println("decodeSignerInfo(): SEQUENCE not found in SignerIdentifier.");
                            return null;
                        }
                    }
                    
                    signer_id = false;
                    digest_id = true;
                }else if(digest_id){
                    AlgorithmIdentifier aid = decodeAlgorithmIdentifier(item);
                    System.out.println("decodeSignerInfo(): Digest Alg ID finished.");
                    if(aid == null){
                        System.out.println("decodeSignerInfo(): Null returned for digest algorithm identifier.");
                        return null;
                    }
                    signer_info.setDigestAlgorithmID(aid);
                    digest_id = false;
                    optional = true;
                }else if(optional){
                    if(item.getTag() == 0){
                        //SignedAttributes
                        ArrayList<Attribute> attrs = decodeSignedAttributes(item);
                        signer_info.setSignedAttributes(attrs);
                        signature_id = true;
                    }else if(item.getTag() == 1){
                        //UnsignedAttributes
                        ArrayList<Attribute> attrs = decodeUnsignedAttributes(item);
                        signer_info.setUnsignedAttributes(attrs);
                    }else{
                        AlgorithmIdentifier aid = decodeAlgorithmIdentifier(item);
                        if(aid == null){
                            System.out.println("decodeSignerInfo(): Null returned for signature algorithm identifier.");
                            return null;
                        }
                        signer_info.setSignatureAlgorithmID(aid);
                        signature_state = true;
                    }

                    optional = false;
                }else if(signature_id){
                    AlgorithmIdentifier aid = decodeAlgorithmIdentifier(item);
                    if(aid == null){
                        System.out.println("decodeSignerInfo(): Null returned for signature algorithm identifier.");
                        return null;
                    }
                    signer_info.setSignatureAlgorithmID(aid);
                    signature_id = false;
                    signature_state = true;
                }else if(signature_state){
                    //SignatureValue ::= OCTET STRING
                    System.out.println("decodeSignerInfo(): Decoding signature---------------------------------------------------------.");
                    byte[] sign = mDecoder.decodeOCTETSTRING(item.getContent());
                    signer_info.setSignature(sign);
                    signature_state = false;
                    optional = true;
                }
            }
        }else{
            return null;
        }
        return signer_info;
    }
    
    public int decodeCMSVersion(ASN1 version){
        //CMSVersion ::= INTEGER {v0(0), v1(1), v2(2), v3(3), v4(4), v5(5)}
        //We do not have depth so we can grab the integer

        //Decode the INTEGER into the version number
        if(mUtil.checkINTEGER(version)){
            int ver = mDecoder.decodeINTEGER(version.getContent());
            return ver;
        }
        return 0;
    }
    
    /** decodeAlgorithmIdentifier() decodes the ASN1 object into an AlgorithmIdentifier, or null if it fails the spec.
     * 
     * @param asn The ASN1 object
     * @return An algorithm identifier
     * @since 1.0
     */
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
                    if(subIDs == null){
                        System.out.println("decodeAlgorithmIdentifier(): Unable to decode sub ids.");
                        return null;
                    }
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
                    return alg_id;
                }
            }
        }else{
            System.out.println("decodeAlgorithmIdentifier(): SEQUENCE expected. Poorly formed.");
            return null;
        }
        return alg_id;
    }
    
    public ArrayList<Attribute> decodeSignedAttributes(ASN1 attrs){
        //SET SIZE (1..MAX) OF Attribute
        ArrayList<Attribute> set = new ArrayList<>();
        if(mUtil.checkSET(attrs) && mUtil.size(attrs) >= 1){
            //Check SET
            for(ASN1 item : attrs.getItems()){
                Attribute attribute = decodeAttribute(item);
                set.add(attribute);
            }
        }
        return set;
    }
    
    public ArrayList<Attribute> decodeUnsignedAttributes(ASN1 attrs){
        //SET SIZE (1..MAX) OF Attribute
        ArrayList<Attribute> set = new ArrayList<>();
        if(mUtil.checkSET(attrs) && mUtil.size(attrs) >= 1){
            //Check SET
            for(ASN1 item : attrs.getItems()){
                Attribute attribute = decodeAttribute(item);
                set.add(attribute);
            }
        }
        return set;
    }
    
    public Attribute decodeAttribute(ASN1 attr){
        //Attribute ::= SEQUENCE {
        //    attrType OBJECT IDENTIFIER
        //    attrValues SET OF AttributeValue }
        Attribute attribute = new Attribute();
        if(mUtil.checkSEQUENCE(attr) && mUtil.size(attr) == 2){
            boolean oi = true;
            
            for(ASN1 item : attr.getItems()){
                if(oi){
                    if(mUtil.checkOBJECTIDENTIFIER(item)){
                        ArrayList<Integer> ids = mDecoder.decodeObjectIdentiferToSubIds(item.getContent());
                        attribute.setIds(ids);
                    }
                }else{
                    //Check for set in tag
                    if(mUtil.checkSET(item)){
                        for(ASN1 value : item.getItems()){
                            //Just add the values
                            attribute.addValue(value);
                        }
                    }
                }
            }
        }
        return attribute;
    }
    
    public IssuerAndSerialNumber decodeIssuerAndSerialNumber(ASN1 is){
        
        //Check if SEQUENCE
        IssuerAndSerialNumber issue = new IssuerAndSerialNumber();
        if(mUtil.checkSEQUENCE(is) && mUtil.size(is) == 2){
            boolean name = true;
            for(ASN1 isn : is.getItems()){
                if(name){
                    issue.setName(isn);
                    name = false;
                }else{
                    //CertificateSerialNumber ::= INTEGER
                    if(mUtil.checkINTEGER(isn)){
                        int csn = mDecoder.decodeINTEGER(isn.getContent());
                        issue.setSerialNumber(csn);
                    }
                }
            }
        }
        return issue;
    }
    
    public OriginatorInfo decodeOriginatorInfo(ASN1 info){
        //OriginatorInfo ::= SEQUENCE {
        //    certs [0] IMPLICIT CertificateSet OPTIONAL,
        //    crls [1] IMPLICIT UnprotectedAttributes OPTIONAL }
        OriginatorInfo oi = new OriginatorInfo();
        if(mUtil.checkSEQUENCE(info) && mUtil.size(info) < 3){
            for(ASN1 item : info.getItems()){
                if(item.getTag() == 0 && mUtil.size(item) == 1){
                    ASN1 inner = item.getItems().get(0);
                    CertificateSet cs = decodeCertificateSet(inner);
                    oi.setCertificateSet(cs);
                }else if(item.getTag() == 1 && mUtil.size(item) == 1){
                    ASN1 inner = item.getItems().get(0);
                    UnprotectedAttributes ua = decodeUnprotectedAttributes(inner);
                    oi.setUnprotectedAttributes(ua);
                }
            }
        }
        return oi;
    }
    
    public RecipientInfos decodeRecipientInfos(ASN1 infos){
        //RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo
        RecipientInfos ri = new RecipientInfos();
        if(mUtil.checkSET(infos) && mUtil.size(infos) >= 1){
            for(ASN1 info : infos.getItems()){
                RecipientInfo recip = decodeRecipientInfo(info);
                ri.addRecipientInfo(recip);
            }
        }
        return ri;
    }
    
    /** decodeEncryptedContentInfo() decodes the ASN1 object into an EncryptedContentInfo object.
     * 
     * @param info The ASN1 object to decode
     * @return An EncryptedContentInfo object.
     * @since 1.0
     */
    public EncryptedContentInfo decodeEncryptedContentInfo(ASN1 info){
        System.out.println("decodeEncryptedContentInfo(): Method called.");
        //EncryptedContentInfo ::= SEQUENCE {
        //    contentType ContentType,
        //    contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
        //    encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }

        EncryptedContentInfo encrypted = new EncryptedContentInfo();
        int size = mUtil.size(info);
        if(mUtil.checkSEQUENCE(info) && (size == 2 || size == 3)){
            boolean type = true;
            boolean alg = false;

            for(ASN1 item : info.getItems()){
                if(type){
                    if(mUtil.checkOBJECTIDENTIFIER(item)){
                        System.out.println("decodeEncryptedContentInfo(): Decoding the content type OID.");
                        ContentType ctype = new ContentType();
                        ctype.setContentType(mDecoder.decodeObjectIdentiferToSubIds(item.getContent()));
                        encrypted.setContentType(ctype);
                    }else{
                        System.out.println("decodeEncryptedContentInfo(): OID was expected.");
                        return null;
                    }
                    type = false;
                    alg = true;
                }else if(alg){
                    System.out.println("decodeEncryptedContentInfo(): Decoding the content encryption algorithm identifier.");
                    ContentEncryptionAlgorithmIdentifier ceai = new ContentEncryptionAlgorithmIdentifier();
                    AlgorithmIdentifier id = decodeAlgorithmIdentifier(item);
                    if(id == null){
                        System.out.println("decodeEncryptedContentInfo(): AlgoriithmIdentifier not decoded. Returned null.");
                        return null;
                    }
                    ceai.setContentEncryptionAlgorithmIdentifier(id);
                    encrypted.setContentEncryptionAlgorithmIdentifier(ceai);
                    alg = false;
                }else{
                    System.out.println("Tag number is " + item.getTag());
                    if(item.getTagNumber() == 0){
                        System.out.println("decodeEncryptedContentInfo(): Decoding the encrypted content as an OCTET STRING.");
                        //IMPLICIT OCTET STRING so we have no depth
                        //ASN1 inner = item.getItems().get(0);
                        EncryptedContent ec = new EncryptedContent();
                        byte[] encr = mDecoder.decodeOCTETSTRING(item.getContent());
                        ec.setEncryptedContent(encr);
                        encrypted.setEncryptedContent(ec);
                        return encrypted;
                    }else{
                        System.out.println("decodeEncryptedContentInfo(): EncryptedContent was poorly formatted.");
                        return null;
                    }
                }
            }
        }else{
            System.out.println("decodeEncryptedContentInfo(): EncryptedContent was poorly formatted.");
            return null;
        }
        return encrypted;
    }
    
    public UnprotectedAttributes decodeUnprotectedAttributes(ASN1 attrs){
        //UnprotectedAttributes ::= SET SIZE (1..MAX) OF Attribute
        UnprotectedAttributes attributes = new UnprotectedAttributes();
        if(mUtil.checkSET(attrs) && mUtil.size(attrs) >= 1){
            for(ASN1 attr : attrs.getItems()){
                Attribute attribute = decodeAttribute(attr);
                attributes.addAttribute(attribute);
            }
        }
        return attributes;
    }
    
    public RecipientInfo decodeRecipientInfo(ASN1 info){
        //RecipientInfo ::= CHOICE {
        //    ktri KeyTransRecipientInfo,
        //    kari [1] KeyAgreeRecipientInfo,
        //    kekri [2] KEKRecipientInfo,
        //    pwri [3] PasswordRecipientInfo,
        //    ori [4] OtherRecipientInfo }
        RecipientInfo rinfo = new RecipientInfo();
        if(mUtil.size(info) == 1){
            for(ASN1 choice : info.getItems()){
                if(choice.getTag() == 1){
                    if(mUtil.size(choice) == 1){
                        ASN1 inner = choice.getItems().get(0);
                        KeyAgreeRecipientInfo kari = decodeKeyAgreeRecipientInfo(inner);
                        rinfo.setKeyAgreeRecipientInfo(kari);
                    }
                }else if(choice.getTag() == 2){
                    if(mUtil.size(choice) == 1){
                        ASN1 inner = choice.getItems().get(0);
                        KEKRecipientInfo kekri = decodeKEKRecipientInfo(inner);
                        rinfo.setKEKRecipientInfo(kekri);
                    }
                }else if(choice.getTag() == 3){
                    if(mUtil.size(choice) == 1){
                        ASN1 inner = choice.getItems().get(0);
                        PasswordRecipientInfo  pwri = decodePasswordRecipientInfo(inner);
                        rinfo.setPasswordRecipientInfo(pwri);
                    }
                }else if(choice.getTag() == 4){
                    if(mUtil.size(choice) == 1){
                        ASN1 inner = choice.getItems().get(0);
                        OtherRecipientInfo ori = decodeOtherRecipientInfo(inner);
                        rinfo.setOtherRecipientInfo(ori);
                    }
                }else{
                    KeyTransRecipientInfo ktri = decodeKeyTransRecipientInfo(choice);
                    rinfo.setKeyTransRecipientInfo(ktri);
                }
            }
        }
        return rinfo;
    }
    
    public KeyTransRecipientInfo decodeKeyTransRecipientInfo(ASN1 ktri){
        //KeyTransRecipientInfo ::= SEQUENCE {
        //    version CMSVersion,
        //    rid RecipientIdentifier,
        //    keyEncryptionAlgorithm KeyEncryptionAlgorithm,
        //    encryptedKey EncryptedKey }
        
        KeyTransRecipientInfo recipient = new KeyTransRecipientInfo();
        if(mUtil.checkSEQUENCE(ktri) && mUtil.size(ktri) == 4){
            boolean version = true;
            boolean rid = false;
            boolean kea_id = false;
            boolean key = false;

            for(ASN1 item : ktri.getItems()){
                if(version){
                    if(mUtil.checkINTEGER(item)){
                        int ver = decodeCMSVersion(item);  //Should be always set to 4
                        recipient.setCMSVersion(ver);
                    }
                    version = false;
                    rid = true;
                }else if(rid){               
                    RecipientIdentifier kda = decodeRecipientIdentifier(item);
                    recipient.setRecipientIdentifier(kda);

                    rid = false;
                    kea_id = true;    
                }else if(kea_id){
                    AlgorithmIdentifier ai = decodeAlgorithmIdentifier(item);
                    KeyEncryptionAlgorithmIdentifier kea = new KeyEncryptionAlgorithmIdentifier();
                    kea.setKeyEncryptionAlgorithmIdentifier(ai);
                    recipient.setKeyEncryptionAlgorithmIdentifier(kea);
                    kea_id = false;
                    key = true;
                }else if(key){
                    //EncryptedKey ::= OCTET STRING  p.45
                    if(mUtil.checkOCTETSTRING(item)){
                        byte[] encrypted_key = mDecoder.decodeOCTETSTRING(item.getContent());
                        recipient.setEncryptedKey(encrypted_key);
                    }
                    key = false;
                }
            }
        }
        return recipient;
    }
    
    public RecipientIdentifier decodeRecipientIdentifier(ASN1 ri){
        //RecipientIdentifier ::= CHOICE {
        //    issuerAndSerialNumber IssuerAndSerialNumber,
        //    subjectKeyIdentifier [0] SubjectKeyIdentifier }
        RecipientIdentifier rid = new RecipientIdentifier();
        if(mUtil.size(ri) == 1){
            for(ASN1 item : ri.getItems()){          
                if(item.getTag() == 0){
                    if(mUtil.size(item) == 1){
                        ASN1 sub = item.getItems().get(0);
                        SubjectKeyIdentifier ski = new SubjectKeyIdentifier();
                        byte[] id = mDecoder.decodeOCTETSTRING(sub.getContent());
                        ski.setSubjectKeyIdentifier(id);
                        rid.setSubjectKeyIdentifier(ski);
                    }
                }else{
                    IssuerAndSerialNumber sn = decodeIssuerAndSerialNumber(item);
                    rid.setIssuerAndSerialNumber(sn);
                }

            }
        }
        return rid;
    }
    
    public KeyAgreeRecipientInfo decodeKeyAgreeRecipientInfo(ASN1 kari){
        //KeyAgreeRecipientInfo ::= SEQUENCE {
        //    version CMSVersion,
        //    originator [0] EXPLICIT OriginatorIdentifierOrKey,
        //    ukm [1] EXPLICIT UserKeyingMaterial OPTIONAL,
        //    keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
        //    recipientEncryptedKeys RecipientEncryptedKeys }
        KeyAgreeRecipientInfo info = new KeyAgreeRecipientInfo();
        int size = mUtil.size(kari);
        if(mUtil.checkSEQUENCE(kari) && (size == 4 || size == 5)){
            boolean version = true;
            boolean originator = false;
            boolean optional = false;
            boolean algorithm = false;
            boolean keys = false;

            for(ASN1 item : kari.getItems()){
                if(version){
                    if(mUtil.checkINTEGER(item)){
                        int cmsversion = decodeCMSVersion(item);
                        info.setCMSVersion(cmsversion);
                    }
                    version = false;
                    originator = true;
                }else if(originator){
                    if(item.getTag() == 0 && mUtil.size(item) == 1){
                        ASN1 orig = item.getItems().get(0);
                        OriginatorIdentifierOrKey oiok = decodeOriginatorIdentifierOrKey(orig);
                        info.setOriginatorIdentifierOrKey(oiok);
                    }
                    originator = false;
                    optional = true;
                }else if(optional){
                    if(item.getTag() == 1){
                        if(mUtil.size(item) == 1){
                            ASN1 keying = item.getItems().get(0);
                            UserKeyingMaterial ukm = decodeUserKeyingMaterial(keying);
                            info.setUserKeyingMaterial(ukm);
                        }
                    }else{
                        KeyEncryptionAlgorithmIdentifier id = new KeyEncryptionAlgorithmIdentifier();
                        AlgorithmIdentifier alg = decodeAlgorithmIdentifier(item);
                        id.setKeyEncryptionAlgorithmIdentifier(alg);
                        info.setKeyEncryptionAlgorithmIdentifier(id);
                        keys = true;
                    }
                    optional = false;
                }else if(algorithm){
                    KeyEncryptionAlgorithmIdentifier id = new KeyEncryptionAlgorithmIdentifier();
                    AlgorithmIdentifier alg = decodeAlgorithmIdentifier(item);
                    id.setKeyEncryptionAlgorithmIdentifier(alg);
                    info.setKeyEncryptionAlgorithmIdentifier(id);
                    algorithm = false;
                    keys = true;
                }else if(keys){
                    RecipientEncryptedKeys reks = decodeRecipientEncryptedKeys(item);
                    info.setRecipientEncryptedKeys(reks);
                }
            }
        }
        return info;
    }
    
    public UserKeyingMaterial decodeUserKeyingMaterial(ASN1 ukm){
        //UserKeyingMaterial ::= OCTET STRING
        UserKeyingMaterial material  = new UserKeyingMaterial();
        if(mUtil.checkOCTETSTRING(ukm)){
            byte[] mat = mDecoder.decodeOCTETSTRING(ukm.getContent());
            material.setUserKeyingMaterial(mat);
        }
        return material;
    }
    
    public OriginatorIdentifierOrKey decodeOriginatorIdentifierOrKey(ASN1 oiok){
        //OriginatorIdentifierOrKey ::= CHOICE {
        //    issuerAndSerialNumber IssuerAndSerialNumber,
        //    subjectKeyIdentifier [0] SubjectKeyIdentifier,
        //    orignatorKey [1] OriginatorPublicKey }
        
        OriginatorIdentifierOrKey k = new OriginatorIdentifierOrKey();
        if(mUtil.size(oiok) == 1){
            boolean isn = true;

            for(ASN1 item : oiok.getItems()){          
                if(item.getTag() == 0){
                    if(mUtil.size(item) == 1){
                        ASN1 sub = item.getItems().get(0);
                        SubjectKeyIdentifier ski = new SubjectKeyIdentifier();
                        byte[] id = mDecoder.decodeOCTETSTRING(sub.getContent());
                        ski.setSubjectKeyIdentifier(id);
                        k.setSubjectKeyIdentifier(ski);
                    }
                }else if(item.getTag() == 1){
                    if(mUtil.size(item) == 1){
                        ASN1 orig = item.getItems().get(0);
                        OriginatorPublicKey opk = decodeOriginatorPublicKey(orig);
                        k.setOrignatorPublicKey(opk);
                    }
                }else{
                    IssuerAndSerialNumber sn = decodeIssuerAndSerialNumber(item);
                    k.setIssuerAndSerialNumber(sn);
                    isn = false;
                }

            }
        }
        return k;
    }
    
    public OriginatorPublicKey decodeOriginatorPublicKey(ASN1 key){
        //OriginatorPublicKey ::= SEQUENCE {
        //    algorithm AlgorithmIdentifier,
        //    publicKey BIT STRING }
        OriginatorPublicKey pk = new OriginatorPublicKey();
        if(mUtil.checkSEQUENCE(key) && mUtil.size(key) == 2){
            boolean algorithm = true;

            for(ASN1 item : key.getItems()){
                if(algorithm){
                    AlgorithmIdentifier identifier = decodeAlgorithmIdentifier(item);
                    pk.setAlgorithmIdentifier(identifier);
                    algorithm = false;
                }else{
                    if(mUtil.checkBITSTRING(item)){
                        //Check if the BITSTRING is primitive or constructed
                        if(item.isConstructed()){
                            BitString public_key = mDecoder.decodeConstructedBITSTRING(item.getItems());
                            pk.setPublicKey(public_key);
                        }else{
                            BitString public_key = mDecoder.decodeBITSTRING(item.getContent());
                            pk.setPublicKey(public_key);
                        }
                    }
                }
            }
        }
        return pk;
    }
    
    public RecipientEncryptedKeys decodeRecipientEncryptedKeys(ASN1 keys){
        //RecipientEncryptedKeys ::= SEQUENCE OF RecipientEncryptedKey
        //Check sequence
        RecipientEncryptedKeys sequence = new RecipientEncryptedKeys();
        if(mUtil.checkSEQUENCEOF(keys)){
            for(ASN1 item : keys.getItems()){
                RecipientEncryptedKey key = new RecipientEncryptedKey();
                key = decodeRecipientEncryptedKey(item);
                sequence.addRecipientKey(key);
            }
        }
        return sequence;
    }
    
    public RecipientEncryptedKey decodeRecipientEncryptedKey(ASN1 key){
        //RecipientEncryptedKey ::= SEQUENCE {
        //    rid KeyAgreeRecipientIdentifier,
        //    encryptedKey EncryptedKey }
        RecipientEncryptedKey rek = new RecipientEncryptedKey();
        if(mUtil.checkSEQUENCE(key) && mUtil.size(key) == 2){
            boolean kari = true;
            //Check SEQUENCE

            for(ASN1 item : key.getItems()){
                if(kari){
                    KeyAgreeRecipientIdentifier identifier = decodeKeyAgreeRecipientIdentifier(item);
                    rek.setKeyAgreeRecipientIdentifier(identifier);
                    kari = false;
                }else{
                    EncryptedKey encrypted_key = decodeEncryptedKey(item);
                    rek.setEncryptedKey(encrypted_key);
                }
            }
        }
        return rek;
    }
    
    public KeyAgreeRecipientIdentifier decodeKeyAgreeRecipientIdentifier(ASN1 kari){
        //KeyAgreeRecipientIdentifier ::= CHOICE {
        //    issuerAndSerialNumber IssuerAndSerialNumber,
        //    rKeyId [0] IMPLICIT RecipientKeyIdentifier }
        KeyAgreeRecipientIdentifier kar = new KeyAgreeRecipientIdentifier();
        if(mUtil.size(kari) == 1){
            for(ASN1 choice : kari.getItems()){
                if(choice.getTag() != 0){
                    IssuerAndSerialNumber is = decodeIssuerAndSerialNumber(choice);
                    kar.setIssuerAndSerialNumber(is);
                }else{
                    if(mUtil.size(choice) == 1){
                        ASN1 id = choice.getItems().get(0);
                        RecipientKeyIdentifier rki = decodeRecipientKeyIdentifier(id);
                        kar.setRecipientKeyIdentifier(rki);                       
                    }
                }
            }
        }
        return kar;
    }
    
    public EncryptedKey decodeEncryptedKey(ASN1 key){
        //EncryptedKey ::= OCTET STRING
        EncryptedKey encrypted_key = new EncryptedKey();
        if(mUtil.checkOCTETSTRING(key)){
            byte[] ek = mDecoder.decodeOCTETSTRING(key.getContent());
            encrypted_key.setEncryptedKey(ek);
        }
        return encrypted_key;
    }
    
    public RecipientKeyIdentifier decodeRecipientKeyIdentifier(ASN1 rki){
        //RecipientKeyIdentifier ::= SEQUENCE {
        //    subjectKeyIdentifier SubjectKeyIdentifier,
        //    date GeneralizedTime OPTIONAL,
        //    other OtherKeyAttribute OPTIONAL }
        RecipientKeyIdentifier recipient_key = new RecipientKeyIdentifier();
        int size = mUtil.size(rki);
        if(mUtil.checkSEQUENCE(rki) && (size >= 1 && size <= 3)){
            boolean kid = true;

            for(ASN1 item : rki.getItems()){
                if(kid){
                    //SubjectKeyIdentifier ::= OCTET STRING
                    if(mUtil.checkOCTETSTRING(item)){
                        byte[] key_identifier = mDecoder.decodeOCTETSTRING(item.getContent());
                        recipient_key.setSubjectKeyIdentifier(key_identifier);
                    }
                    kid = false;
                }else{
                    //OPTIONAL ones
                    if(mUtil.checkGeneralizedTime(item)){  //GeneralizedTime - pretend
                        recipient_key.setGeneralizedTime(item);
                    }else{
                        //OtherKeyAttribute
                        OtherKeyAttribute attribute = decodeOtherKeyAttribute(item);
                        recipient_key.setOtherKeyAttribute(attribute);
                    }
                }
            }
        }
        return recipient_key;
    }
    
    public KEKRecipientInfo decodeKEKRecipientInfo(ASN1 kek){
        //KEKRecipientInfo ::= SEQUENCE {
        //    version CMSVersion,    --always set to 4
        //    kekid KEKIdentifier,
        //    keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
        //    encryptedKey EncryptedKey }
        KEKRecipientInfo recipient = new KEKRecipientInfo();
        if(mUtil.checkSEQUENCE(kek) && mUtil.size(kek) == 4){
            boolean version = true;
            boolean kek_id = false;
            boolean kea_id = false;
            boolean key = false;

            for(ASN1 item : kek.getItems()){
                if(version){
                    int ver = decodeCMSVersion(item);  //Should be always set to 4
                    recipient.setCMSVersion(ver);
                    version = false;
                    kek_id = true;
                }else if(kek_id){ 
                    if(mUtil.size(item) == 1){
                        ASN1 alg = item.getItems().get(0);
                        KEKIdentifier kda = decodeKEKIdentifier(alg);
                        recipient.setKEKIdentifier(kda);
                    } 
                    kek_id = false;
                    kea_id = true;    
                }else if(kea_id){
                    AlgorithmIdentifier kea = decodeAlgorithmIdentifier(item);
                    recipient.setKeyEncryptionAlgorithmIdentifier(kea);
                    kea_id = false;
                    key = true;
                }else if(key){
                    //EncryptedKey ::= OCTET STRING  p.45
                    if(mUtil.checkOCTETSTRING(item)){
                        byte[] encrypted_key = mDecoder.decodeOCTETSTRING(item.getContent());
                        recipient.setEncryptedKey(encrypted_key);
                    }
                    key = false;
                }
            }
        }
        return recipient;
    }
    
    public KEKIdentifier decodeKEKIdentifier(ASN1 kek){
        //KEKIdentifier ::= SEQUENCE {
        //    keyIdentifier OCTET STRING,
        //    date GeneralizedTime OPTIONAL,
        //    other OtherKeyAttribute OPTIONAL }
        KEKIdentifier kek_id = new KEKIdentifier();
        int size = mUtil.size(kek);
        if(mUtil.checkSEQUENCE(kek) && (size >= 1 && size <= 3)){
            boolean kid = true;

            for(ASN1 item : kek.getItems()){
                if(kid){
                    byte[] key_identifier = mDecoder.decodeOCTETSTRING(item.getContent());
                    kek_id.setKeyIdentifier(key_identifier);
                    kid = false;
                }else{
                    //OPTIONAL ones
                    if(item.getTag() == 1){  //GeneralizedTime - pretend
                        kek_id.setGeneralizedTime(item);
                    }else{
                        //OtherKeyAttribute
                        OtherKeyAttribute attribute = decodeOtherKeyAttribute(item);
                        kek_id.setOtherKeyAttribute(attribute);
                    }
                }
            }
        }
        return kek_id;
    }
    
    public PasswordRecipientInfo decodePasswordRecipientInfo(ASN1 info){
        //PasswordRecipientInfo ::= SEQUENCE {
        //    version CMSVersion,
        //    keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier OPTIONAL,
        //    keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
        //    encryptedKey EncryptedKey }
        PasswordRecipientInfo password = new PasswordRecipientInfo();
        int size = mUtil.size(info);
        if(mUtil.checkSEQUENCE(info) && (size == 3 || size == 4)){
            //Check for SEQUENCE
            boolean version = true;
            boolean kda_id = false;
            boolean kea_id = false;
            boolean key = false;

            for(ASN1 item : info.getItems()){
                if(version){
                    int ver = decodeCMSVersion(item);
                    password.setCMSVersion(ver);
                    version = false;
                    kda_id = true;
                }else if(kda_id){
                    if(item.getTag() == 0){
                        if(mUtil.size(item) == 1){
                            ASN1 alg = item.getItems().get(0);
                            AlgorithmIdentifier kda = decodeAlgorithmIdentifier(alg);
                            password.setKeyDerivationAlgorithmIdentifier(kda);
                        }
                        kda_id = false;
                        kea_id = true;
                    }else{
                        AlgorithmIdentifier kea = decodeAlgorithmIdentifier(item);
                        password.setKeyEncryptionAlgorithmIdentifier(kea);
                        key = true;
                    }

                }else if(kea_id){
                    AlgorithmIdentifier kea = decodeAlgorithmIdentifier(item);
                    password.setKeyEncryptionAlgorithmIdentifier(kea);
                    kea_id = false;
                    key = true;
                }else if(key){
                    //EncryptedKey ::= OCTET STRING  p.45
                    if(mUtil.checkOCTETSTRING(item)){
                        byte[] encrypted_key = mDecoder.decodeOCTETSTRING(item.getContent());
                        password.setEncryptedKey(encrypted_key);
                    }
                    key = false;
                }
            }
        }
        return password;
    }
    
    public OtherRecipientInfo decodeOtherRecipientInfo(ASN1 info){
        //OtherRecipientInfo ::= SEQUENCE {
        //    oriType OBJECT IDENTIFIER,
        //    oriValue ANY DEFINED BY oriType}
        OtherRecipientInfo ori = new OtherRecipientInfo();
        if(mUtil.checkSEQUENCE(info) && mUtil.size(info) == 2){
            boolean oi = true;

            for(ASN1 item : info.getItems()){
                if(oi){
                    if(mUtil.checkOBJECTIDENTIFIER(item)){
                        ObjectIdentifier identifier = compileObjectIdentifier(item.getContent());
                        ori.setID(identifier);
                    }
                    oi = false;
                }else{
                    //Save the ASN1
                    ori.setValue(item);
                }
            }
        }
        return ori;
    }
    
    public OtherKeyAttribute decodeOtherKeyAttribute(ASN1 info){
        //OtherKeyAttribute ::= SEQUENCE {
        //    keyAttrId OBJECT IDENTIFIER,
        //    keyAttr ANY DEFINED BY keyAttrId OPTIONAL}
        OtherKeyAttribute ori = new OtherKeyAttribute();
        int size = mUtil.size(info);
        if(mUtil.checkSEQUENCE(info) && (size == 1 || size == 2)){
            boolean oi = true;

            //Check tag is SEQUENCE
            for(ASN1 item : info.getItems()){
                if(oi){
                    if(mUtil.checkOBJECTIDENTIFIER(item)){
                        ObjectIdentifier identifier = compileObjectIdentifier(item.getContent());
                        ori.setID(identifier);
                    }
                    oi = false;
                }else{
                    //Save the ASN1
                    ori.setAttribute(item);
                }
            }
        }
        return ori;
    }
    
    //Helper
    public ObjectIdentifier compileObjectIdentifier(byte[] content){
        ObjectIdentifier identifier = new ObjectIdentifier();
        ArrayList<Integer> ids = mDecoder.decodeObjectIdentiferToSubIds(content);
        identifier.setObjectIdentifier(ids);
        return identifier;
    }
}

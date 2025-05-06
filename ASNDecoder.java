/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ASN1;

import Utilities.ByteArrayProcessor;
import Utilities.Utilities;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Stack;


/**
 *
 * @author Owen
 */
public class ASNDecoder {
    Charset charset = Charset.forName("us-ascii");
    
    ASN1Result result = new ASN1Result();
    
    Utilities mUtils = new Utilities();
    
    ASNUtils asnUtils = new ASNUtils();
    
    ByteArrayProcessor mProcessor = new ByteArrayProcessor();
    
    //This stack holds the resolved 'primitive' types in order of parsing.
    Stack<byte[]> tree = new Stack<>();
    
    //Special control
    int depthControl = 0;
    
    //TEST 
    int i = 0;
    
    public ASNDecoder(){
        
    }
    
    public void init(){
        
    }
    
    /** genericDecode() decodes the ASN1 encoded object. The ASN1 object is recursively designed so that each level within it can
     * be easily accessed.
     * 
     * @param input - The object to decode
     * @return ASN1 - The asn1 object
     * @since 1.0
     */
    public ASN1 genericDecode(byte[] input){  //returns ASN1
        //System.out.println("genericDecode(): Method called.");
        //i++;
        ASN1 asn = new ASN1();
        
        
        //Tag identifier
        boolean tag = true;
        boolean tagFirstOctet = true;
        boolean tag_extended = false;
        
        //Length octets
        boolean length = false;
        boolean length_first_octet = false;
        boolean length_extended = false;
        
        //Bits 8 and 7
        boolean universal = false; //00
        boolean application = false; //01
        boolean contextSpecific = false;  //10
        boolean priv = false;  //11
        
        //Bit 6
        boolean constructed = false;
        
        //The tag currently being processed
        int current_tag = 0;
        
        //Number of octets used to denote the length
        int length_octets = 0;
        
        int content_length = 0;
        
        Stack<Byte> tag_stack = new Stack<>();
        Stack<Byte> length_stack = new Stack<>();
        Stack<Byte> stack = new Stack<>();
        byte[] bytes = null;
        int index = 0; //index into bytes
        
        //System.out.println("genericDecode(): Starting on the tag/id.");
        for(byte b : input){
            if(tag){
                if(tagFirstOctet){
                    //We process the first tag
                    if(mUtils.checkBit(b, 7) && mUtils.checkBit(b, 6)){
                        //11 Private
                        priv = true;
                        //System.out.println("genericDecode(): Private bits set in tag.");
                    }else if(!mUtils.checkBit(b, 7) && !mUtils.checkBit(b, 6)){
                        //00 Universal
                        universal = true;
                        asn.setUniversal();
                        //System.out.println("genericDecode(): Universal bits set to 00 in tag.");
                    }else if(mUtils.checkBit(b, 7) && !mUtils.checkBit(b, 6)){
                        //10 Context spec
                        contextSpecific = true;
                        asn.setContextSpecific();
                        //System.out.println("genericDecode(): Context specific bit set in tag.");
                    }else if(!mUtils.checkBit(b, 7) && mUtils.checkBit(b, 6)){
                        //01 Application
                        application = true;
                        //System.out.println("genericDecode(): Application bit set in tag.");
                    }
                    
                    //Next we look at bit 6 (position 5)
                    if(mUtils.checkBit(b, 5)){
                        //constructed
                        //System.out.println("genericDecode(): Tag is constructed. Setting constructed field.");
                        constructed = true;
                        asn.setConstructed();
                    }else{
                        //System.out.println("genericDecode(): Tag is primitive.");
                    }
                    //We decode bits 1 to 5 (tag or 31)
                    int short_bit = decodeShortBit(b);
                    
                    if(short_bit == 31){
                        //All five bits are set to 1
                        //id >= 31
                        tag_extended = true;
                        //System.out.println("genericDecode(): All five bits are set to 1. We expect additional octets encoding the tag.");
                    }else{                      
                        //This isolates a tag in [].
                        if(contextSpecific){
                            asn.setTag((byte) short_bit);  // 0, 1, 2, 3 (most common)
                            asn.setTagNumber(short_bit);
                            asn.setTagByte((byte) short_bit);
                            current_tag = short_bit;
                        }else{
                            asn.setTagNumber(short_bit);
                            asn.setTag((byte) short_bit);
                            asn.setTagByte(b);
                        }
                        current_tag = short_bit;
                        
                        //asn.setTagNumber(short_bit);
                        tagFirstOctet = false;
                        tag = false;
                        length = true;
                        length_first_octet = true;
                        //System.out.println("genericDecode(): Tag number is " + current_tag + ". Moving to length octet(s) processing state.");
                    }
                }else if(tag_extended){
                    if(mUtils.checkBit(b, 7)){
                        //System.out.println("genericDecode(): On the last byte of the identifier.");
                        //This is the last octet.
                        //Process the tag stack
                        tag_extended = false;
                        tag = false;
                        length = true;
                        length_first_octet = true;
                        tag_stack.add(b);
                        //Decode the tag, and set the tag number in the ASN object.
                        int t = decodeIdentifierOctets(tag_stack);
                        //System.out.println("genericDecode(): The extended tag number is " + t);
                        current_tag = t;
                        //asn.setTagNumber(t);
                        tag_stack.clear();
                    }else{
                        tag_stack.add(b);
                    }
                }
            }else if(length){
                if(length_first_octet){
                    //We check bit 8 to see if we are in the short form or long form
                    if(mUtils.checkBit(b, 7)){
                        //System.out.println("genericDecode(): We have the long form of length.");
                        //We may now have the long form or the indefinite form.
                        if(b == -128){
                            //Indefinite form (bits 7 to 1 are all 0)
                            //System.out.println("decodeGeneric(): We have the indefinite form of length.");
                            
                        }else{
                            //Determine the number of length octets from bits 7 to 1
                            length_octets = decode7Bit(b);
                            //System.out.println("genericDecode(): The number of octets containing the encoding of the content length is " +
                            //        length_octets);
                        }
                        
                        length_first_octet = false;
                        length_extended = true;
                    }else{
                        //The short form is a basic unsigned binary encoding, so we can directly set the length without decoding. (Bit 8 cant be set)
                        asn.setLength((int) b); 
                        content_length = b;
                        length = false;
                        length_first_octet = false;
                        //Initialize the byte array
                        //bytes = new byte[content_length];
                        //System.out.println("genericDecode(): The length was determined to be " + b + ". Moving to contents state.");
                    }
                }else if(length_extended){
                    length_stack.add(b);
                    if(length_stack.size() == length_octets){
                        //process the length stack
                        content_length = decodeLengthOctets(length_stack);
                        length_octets = 0;
                        //System.out.println("genericDecode(): We have determined the length to be " + content_length);
                        length_extended = false;
                        length = false;
                        length_stack.clear();
                        //Initialize bytes
                        //bytes = new byte[content_length];
                    }
                }
            }else{
                //We collect the bytes based on the declared number of octets
                
                //index = 0; //Reset index
                stack.add(b);
                //bytes[index] = b;
                index++;
                if(stack.size() == content_length){
                    //System.out.println("genericDecode(): We have read in the contents. Now we handle the results.");
                    //We've finished this item. If we have a constructed type then we call this method recursively adding to the tree as we 
                    //reach primitive types.
                    if(!stack.isEmpty()){
                        byte[] temp = mUtils.compile(stack);
                        if(constructed){
                            //
                            //System.out.println("genericDecode(): Calling genericDecodeConstructed().");
                            genericDecodeConstructed(asn, temp);
                            //ASN1 rec = new ASN1();
                            //rec.setContent(temp);
                            //rec.setConstructed();
                            asn.setContent(temp);
                            //asn.addItem(rec);
                            //TEST
                            
                            asn.setConstructed();
                            //System.out.println("genericDecode(): The number of items in the current ASN1 structure is " + asn.size());
                            constructed = false;
                        }else{
                            //System.out.println("genericDecode(): Primitive content set.");
                            ASN1 rec = new ASN1();
                            rec.setContent(temp);
                            //asn.setContent(temp);
                            asn.addItem(rec);
                            //System.out.println("genericDecode(): The number of items in the current ASN1 structure is " + asn.size());
                            //tree.add(temp);  //I dont think i need this...
                        }
                        stack.clear();
                    }else{
                        //System.out.println("genericDecode(): Stack is empty in the contents state. Must be an empty object...");
                    }
                    //System.out.println("genericDecode(): Content has been handled. Moving to tag state.");
                    tag = true;
                    tagFirstOctet = true;
                    //bytes = null;
                    length_stack.clear();
                    tag_stack.clear();
                    content_length = 0;
                }
            }
        }
        return asn;
    }
    
    /** genericDecodeConstructed() decodes the constructed object encoded in 'content'.
     * 
     * @param parent - The parent ASN1 object to add the lower levels to.
     * @param content - The encoded constructed object
     * @since 1.0
     */
    public void genericDecodeConstructed(ASN1 parent, byte[] content){
        //System.out.println("genericDecodeConstructed(): Method called.");
        //We go through and build indiviual ASN1 objects for this constructed ASN1 object. The object passed in is the high level object, and as 
        //we parse each lower level object it is added to the list.
        boolean tag = true;
        boolean tagFirstOctet = true;
        boolean tag_extended = false;
        
        //Length octets
        boolean length = false;
        boolean length_first_octet = false;
        boolean length_extended = false;
        
        //Bits 8 and 7
        boolean universal = false; //00
        boolean application = false; //01
        boolean contextSpecific = false;  //10
        boolean priv = false;  //11
        
        //Bit 6
        boolean constructed = false;
        
        //The tag currently being processed
        int current_tag = 0;
        
        //Number of octets used to denote the length
        int length_octets = 0;
        
        int content_length = 0;
        
        Stack<Byte> tag_stack = new Stack<>();
        Stack<Byte> length_stack = new Stack<>();
        Stack<Byte> stack = new Stack<>();
        
        ASN1 asn = new ASN1(); //Current child ASN1 object
        
        for(byte b : content){
            if(tag){
                if(tagFirstOctet){
                    //We (re)initialize the asn object
                    asn = new ASN1();
                    
                    //We process the first tag
                    if(mUtils.checkBit(b, 7) && mUtils.checkBit(b, 6)){
                        //11 Private
                        priv = true;
                        //System.out.println("genericDecodeConstructed(): Private bits set in tag.");
                    }else if(!mUtils.checkBit(b, 7) && !mUtils.checkBit(b, 6)){
                        //00 Universal
                        universal = true;
                        asn.setUniversal();
                        //System.out.println("genericDecodeConstructed(): Universal bits set to 00 in tag.");
                    }else if(mUtils.checkBit(b, 7) && !mUtils.checkBit(b, 6)){
                        //10 Context spec
                        contextSpecific = true;
                        asn.setContextSpecific();
                        //System.out.println("genericDecodeConstructed(): Context specific bit set in tag.");
                    }else if(!mUtils.checkBit(b, 7) && mUtils.checkBit(b, 6)){
                        //01 Application
                        application = true;
                        //System.out.println("genericDecodeConstructed(): Application bit set in tag.");
                    }
                    
                    //Next we look at bit 6 (position 5)
                    if(mUtils.checkBit(b, 5)){
                        //constructed
                        //System.out.println("genericDecodeConstructed(): Tag is constructed. Setting constructed field.");
                        constructed = true;
                        asn.setConstructed();
                    }else{
                        //System.out.println("genericDecodeConstructed(): Tag is primitive.");
                    }
                    //We decode bits 1 to 5 (tag or 31)
                    int short_bit = decodeShortBit(b);
                    
                    if(short_bit == 31){
                        //All five bits are set to 1
                        //id >= 31
                        tag_extended = true;
                        //System.out.println("genericDecodeConstructed(): All five bits are set to 1. We expect additional octets encoding the tag.");
                    }else{                      
                        //This isolates a tag in [].
                        if(contextSpecific){
                            asn.setTag((byte) short_bit);  // 0, 1, 2, 3 (most common)
                            asn.setTagNumber(short_bit);
                            asn.setTagByte((byte) short_bit);
                            current_tag = short_bit;
                        }else{
                            asn.setTagNumber(short_bit);
                            asn.setTag((byte) short_bit);
                            asn.setTagByte(b);
                        }
                        current_tag = short_bit;
                        
                        //asn.setTagNumber(short_bit);
                        tagFirstOctet = false;
                        tag = false;
                        length = true;
                        length_first_octet = true;
                        //System.out.println("genericDecodeConstructed(): Tag number is " + current_tag + ". Moving to length octet(s) processing state.");
                    }
                }else if(tag_extended){
                    if(mUtils.checkBit(b, 7)){
                        //System.out.println("genericDecodeConstructed(): On the last byte of the identifier.");
                        //This is the last octet.
                        //Process the tag stack
                        tag_extended = false;
                        tag = false;
                        length = true;
                        length_first_octet = true;
                        tag_stack.add(b);
                        //Decode the tag, and set the tag number in the ASN object.
                        int t = decodeIdentifierOctets(tag_stack);
                        //System.out.println("genericDecodeConstructed(): The extended tag number is " + t);
                        current_tag = t;
                        //asn.setTagNumber(t);
                        tag_stack.clear();
                    }else{
                        tag_stack.add(b);
                    }
                }
            }else if(length){
                if(length_first_octet){
                    //We check bit 8 to see if we are in the short form or long form
                    if(mUtils.checkBit(b, 7)){
                        //System.out.println("genericDecodeConstructed(): We have the long form of length.");
                        //We may now have the long form or the indefinite form.
                        if(b == -128){
                            //Indefinite form (bits 7 to 1 are all 0)
                            //System.out.println("decodeGenericConstructed(): We have the indefinite form of length.");
                            
                        }else{
                            //Determine the number of length octets from bits 7 to 1
                            length_octets = decode7Bit(b);
                            //System.out.println("genericDecodeConstructed(): The number of octets containing the encoding of the content length is " +
                            //        length_octets);
                        }
                        
                        length_first_octet = false;
                        length_extended = true;
                    }else{
                        //The short form is a basic unsigned binary encoding, so we can directly set the length without decoding. (Bit 8 cant be set)
                        asn.setLength((int) b); 
                        content_length = b;
                        length = false;
                        length_first_octet = false;
                        //Initialize the byte array
                        //bytes = new byte[content_length];
                        //System.out.println("genericDecodeConstructed(): The length was determined to be " + b + ". Moving to contents state.");
                    }
                }else if(length_extended){
                    length_stack.add(b);
                    if(length_stack.size() == length_octets){
                        //process the length stack
                        content_length = decodeLengthOctets(length_stack);
                        length_octets = 0;
                        //System.out.println("genericDecodeConstructed(): We have determined the length to be " + content_length);
                        length_extended = false;
                        length = false;
                        length_stack.clear();
                        //Initialize bytes
                        //bytes = new byte[content_length];
                    }
                }
            }else{
                //We collect the bytes based on the declared number of octets
                
                //index = 0; //Reset index
                stack.add(b);
                //bytes[index] = b;
                //index++;
                if(stack.size() == content_length){
                    //System.out.println("genericDecodeConstructed(): We have read in the contents. Now we handle the results.");
                    //We've finished this item. If we have a constructed type then we call this method recursively adding to the tree as we 
                    //reach primitive types.
                    if(!stack.isEmpty()){
                        byte[] temp = mUtils.compile(stack);
                        
                        if(constructed){
                            //
                            //System.out.println("genericDecodeConstructed(): Recursively calling genericDecodeConstructed().");
                            genericDecodeConstructed(asn, temp);
                            //NOTE: For right now hold off on adding the content bytes of a constructed object.
                            //ASN1 rec = new ASN1();
                            //rec.setContent(temp);
                            //rec.setConstructed();
                            asn.setContent(temp);
                            //asn.addItem(rec);
                            //TEST
                            
                            asn.setConstructed();
                            ASN1 copy = asn;
                            parent.addItem(copy);
                            //System.out.println("genericDecodeConstructed(): The number of items in the current ASN1 structure is " + asn.size());
                            constructed = false;
                        }else{
                            //System.out.println("genericDecodeConstructed(): Primitive content set.");
                            asn.setContent(temp);
                            ASN1 rec = asn;  //copy
                            //rec.setContent(temp);
                            //asn.setContent(temp);
                            parent.addItem(rec);
                            //System.out.println("genericDecode(): The number of items in the current ASN1 structure is " + asn.size());
                            //tree.add(temp);  //I dont think i need this...
                        }
                        stack.clear();
                    }else{
                        //System.out.println("genericDecodeConstructed(): Stack is empty in the contents state. Must be an empty object...");
                    }
                    //System.out.println("genericDecodeConstructed(): Content has been handled. Moving to tag state.");
                    tag = true;
                    tagFirstOctet = true;
                    //bytes = null;
                    length_stack.clear();
                    tag_stack.clear();
                    content_length = 0;
                    priv = false;
                    universal = false;
                    contextSpecific = false;
                    application = false;
                }
            }
        }
    }
    
    /** decodeInteger() decodes the bytes passed in and returns an integer. The encoding is in 2's complement. The algorithm is basic,
     * and starts with the last byte's position 0 (first bit) and counts each bit from right to left (if you will). Each time a 1 is
     * encountered the result is increased by Math.pow(2, i) until the final bit is reached. If this bit is reached then the result 
     * is subtracted by Math.pow(2, i).
     *
     * @param bytes - The encoded bytes
     * @return int - The decoded integer.
     * @since 1.0
     */
    public int decodeINTEGER(byte[] bytes){
        //System.out.println("decodeINTEGER(): Method called.");
        int res = 0;
        int count = 0;
        //We begin with the last byte
        for(int i = bytes.length - 1; i >= 0; i--){
            byte b = bytes[i];
            //System.out.println("decodeINTEGER(): Processing byte " + b);
            //We iterate through and check each bit, increasing count as we go along.
            for(int t = 0; t < 8; t++){
                if(mUtils.checkBit(b, t)){
                    //System.out.println("decodeINTEGER(): Bit found at local position " + t + ", global position " + count);
                    //We check the highest bit to determine if its a 1 (negative)
                    if(i == 0 && t == 7){
                        //System.out.println("decodeINTEGER(): We have a negative integer.");
                        //We have a negative integer
                        res -= Math.pow(2, count);
                    }else{
                        res += Math.pow(2, count);
                    }
                }
                count++;
            }
        }
        return res;
    }
    
    /** decodeObjectIdentifierToSubIds() iterates through the series of encoded unsigned binary numbers and adds them to the final list.
     *
     * @param bytes - The series of sub ids.
     * @return The sub ids, in order.
     * @since 1.0
     */
    public ArrayList<Integer> decodeObjectIdentiferToSubIds(byte[] bytes){
        //System.out.println("decodeObjectIdentifierToSubIds(): Method called.");
        //The bytes are an ordered list of subidentifiers.
        //Bit 8 of the last octet of a subidentifier is 0, each preceding is 1. We stop when we reach 0 and call decodeUnsignedNumber().
        //Each decoded subidentifier is added to the results list.
        ArrayList<Integer> results = new ArrayList<>();
        Stack<Byte> current = new Stack<>();
        
        for(byte b : bytes){
            if(!mUtils.checkBit(b, 7)){
                //Bit 8 is 0, hence we process the current stack of bytes and build the unsigned number
                current.add(b);
                //We borrow the identifier octet decoder (could wrap this in something more elegant)
                int number = decodeIdentifierOctets(current);
                results.add(number);
                current.clear();
            }else{
                current.add(b);
            }
        }
        return results;
    }   
    
    //4
    /** decodeOCTETSTRING() is a simple method that returns the contents as is.
     *
     * @param content - The octet string contents
     * @return byte[] - The octet string
     *
     */
    public byte[] decodeOCTETSTRING(byte[] content){
        //Primitive resolution
        //System.out.println("decodeOCTETSTRING(): Method called.");
        return content;
    }
    
    //4
    /** decodeConstructedOCTETSTRING() recursively extracts the octet string parts and compiles the results.
     *
     * @param items - The current level ASN1 objects 
     * @return byte[] - The extracted and compiled octet string.
     * @since 1.0
     */
    public byte[] decodeConstructedOCTETSTRING(ArrayList<ASN1> items){
        //Constructed resolution
        //System.out.println("decodeConstructedOCTETSTRING(): Method called.");
        ArrayList<byte[]> results = new ArrayList<>();
        
        for(ASN1 item : items){
            //We see if we need to recursively parse it
            if(item.isConstructed()){
                //System.out.println("decodeConstructedOCTETSTRING(): Recursively calling the method.");
                byte[] bytes = decodeConstructedOCTETSTRING(item.getItems());
                results.add(bytes);
            }else{
                //System.out.println("decodeConstructedOCTETSTRING(): Finishing a primitive octet string.");
                byte[] bytes = decodeOCTETSTRING(item.getContent());
                results.add(bytes);
            }
        }
        
        return mProcessor.compileArrays(results);
    }
    
    //3
    /** decodeBITSTRING() decodes the primitive bitstring and fills the BitString object. I use a BitString object to convey the number of 
     * trailing zeros.
     *
     * @param content - The bitstring to decode
     * @return BitString - The filled object.
     * @since 1.0
     */
    public BitString decodeBITSTRING(byte[] content){
        //Universal 3 - Primitive resolution
        //System.out.println("decodeBITSTRING(): Method called.");
        int unused;
        
        if(content.length <= 0){
            //System.out.println("decodeBITSTRING(): No content in content.");
            //Stop
            return null;
        }
        //We look at the first byte
        byte b = content[0];
        
        //Decode the unsigned binary integer
        unused = this.decode7Bit(b);
        
        //Check the value
        if(unused < 0 || unused > 7){
            //System.out.println("decodeBITSTRING(): Unused value out of bounds.");
            //Stop
            return null;
        }
        
        //System.out.println("decodeBITSTRING(): Isolating the remaining bytes.");
        //Isolate the remaining bytes
        byte[] res = mProcessor.subarray(content, 1, content.length - 1);
        
        //Fill out the object
        BitString bit_string = new BitString();
        bit_string.setBitString(res);
        bit_string.setUnused(unused);
        return bit_string;
    }
    
    /** decodeConstructedBITSTRING() takes a list of ASN1 objects and recursively extracts the bitstrings. These are then compiled into the 
     * final BitString object.
     *
     * @param list - The list of same level ASN1 objects.
     * @return BitString
     * @since 1.0
     */
    public BitString decodeConstructedBITSTRING(ArrayList<ASN1> list){
        //Constructed resolution
        //We start on the top level
        //System.out.println("decodeConstructedBITSTRING(): Method called.");
        ArrayList<byte[]> results = new ArrayList<>();
        int unused = 0;
        
        for(ASN1 item : list){
            if(item.isConstructed()){
                //Recursive call
                //System.out.println("decodeConstructedBITSTRING(): Recursive ASN1 object.");
                BitString bs = decodeConstructedBITSTRING(item.getItems());
                results.add(bs.getBitString());
                if(bs.getUnused() > 0){
                    unused = bs.getUnused();
                }
            }else{                
                //I make the assumption that there are no unused bytes in each part except the final part.
                //System.out.println("decodeConstructedBITSTRING(): decoding a primitive bitstring.");
                BitString bs = decodeBITSTRING(item.getContent());
                results.add(bs.getBitString());
                if(bs.getUnused() > 0){
                    unused = bs.getUnused();
                }
            }
        }
        //System.out.println("decodeConstructedBITSTRING(): Compiling the extracted bitstring parts.");
        //We compile the extracted bitstring parts, and fill out the final object
        byte[] string = mProcessor.compileArrays(results);
        BitString bit_string = new BitString();
        bit_string.setBitString(string);
        //Set unused
        bit_string.setUnused(unused);
        return bit_string;
    }
    
    //1
    /** decodeBOOLEAN() decodes the boolean object.
     *
     * @param content - The content octet(s)
     * @return boolean - True or false, as per the encoding
     * @since 1.0
     * @tested October 24, 2021
     */
    public boolean decodeBOOLEAN(byte[] content){
        //Octet == 0 we have false, true for any other value.
        //System.out.println("decodeBOOLEAN(): Method called.");
        if(content == null || content.length != 0){
            //System.out.println("decodeBOOLEAN(): Content octets poorly formatted.");
            return false;
        }
        return content[0] != 0;       
    }
    
    //9
    /** decodeREAL() decodes the encoded REAL value into a Real object.
     *
     * @param content
     * @return Real - The filled Real object, or null if it failed
     * @since 1.0
     */
    public Real decodeREAL(byte[] content){
        System.out.println("decodeREAL(): Method called.");
        Real real = new Real();
        boolean prelude = true;
        boolean exponent = false;
        boolean exponent_next = false;
        int exponent_size = 0;
        Stack<Byte> stack = new Stack<>();
        
        for(byte b : content){
            if(prelude){
                //We check the first byte for details
                if(mUtils.checkBit(b, 7)){
                    //We have a binary encoding
                    System.out.println("decodeREAL(): Bit 8 set. We have a binary encoding.");
                    //Start with bit 7
                    if(mUtils.checkBit(b, 6)){
                        real.setS(-1);
                    }else{
                        real.setS(1);
                    }
                    
                    //Handle bits 6 and 5
                    if(!mUtils.checkBit(b, 5) && !mUtils.checkBit(b, 4)){  //00
                        real.setBase(2);
                    }else if(!mUtils.checkBit(b, 5) && mUtils.checkBit(b, 4)){
                        real.setBase(8);
                    }else if(mUtils.checkBit(b, 5) && !mUtils.checkBit(b, 4)){
                        real.setBase(16);
                    }else{
                        //reserved, leave as initial value
                    }
                    
                    //Determine the scaling factor from bits 4 and 3
                    if(mUtils.checkBit(b, 3) && mUtils.checkBit(b, 2)){
                        real.setF(3);
                    }else if(mUtils.checkBit(b, 3) && !mUtils.checkBit(b, 2)){
                        real.setF(2);
                    }else if(!mUtils.checkBit(b, 3) && mUtils.checkBit(b, 2)){
                        real.setF(1);
                    }else{
                        real.setF(0);
                    }
                    
                    if(!mUtils.checkBit(b, 1) && !mUtils.checkBit(b, 0)){
                        exponent_size = 1;
                    }else if(!mUtils.checkBit(b, 1) && mUtils.checkBit(b, 0)){
                        exponent_size = 2;
                    }else if(mUtils.checkBit(b, 1) && !mUtils.checkBit(b, 0)){
                        exponent_size = 3;
                    }else{
                        System.out.println("decodeREAL(): We have a large exponent. Moving to exponent_next state.");
                        exponent_next = true;
                    }
                    System.out.println("decodeREAL(): Moving to exponent state.");
                    //We move into the exponent processing state
                    exponent = true;   
                }else{
                    if(mUtils.checkBit(b, 6)){
                        //We have the special real value
                        System.out.println("decodeREAL(): We have a special real value.");
                        if(mUtils.checkBit(b, 1)){
                            //minus-infinity
                            real.setInfinity("negative");
                        }else{
                            //positive-infinity
                            real.setInfinity("positive");
                        }
                        return real;
                    }else{
                        //We have a decimal encoding, lets determine the form type with the last two bits
                        System.out.println("decodeREAL(): We have a decimal encoding.");
                        if(mUtils.checkBit(b, 1) && mUtils.checkBit(b, 0)){
                            //NR3 form
                            real.setDecimalForm("NR3");
                        }else if(mUtils.checkBit(b, 1) && !mUtils.checkBit(b, 0)){
                            //NR2 form
                            real.setDecimalForm("NR2");
                        }else if(!mUtils.checkBit(b, 1) && mUtils.checkBit(b, 0)){
                            //NR1 form
                            real.setDecimalForm("NR1");
                        }else{
                            return null;
                        }
                        
                        //Add the contents
                        real.setDecimalBytes(mProcessor.subarray(content, 1, content.length - 1));
                        return real;
                    }
                }
            }else if(exponent){
                if(exponent_next){
                    exponent_size = decodeUnsignedBinaryInteger(new byte[]{b});
                    System.out.println("decodeREAL(): Determined the size of the exponent to be " + exponent_size + " in the exponent_next state.");
                    exponent_next = false;
                }else{
                    //We add the bytes to the stack until we have the required number of bytes
                    stack.add(b);
                    if(stack.size() == exponent_size){
                        System.out.println("decodeREAL(): Decoding the exponent.");
                        real.setE(decodeUnsignedBinaryInteger(stack));
                        stack.clear();
                        exponent = false;
                    }
                }
            }else{
                //We collect the encoded n
                stack.add(b);
            }
        }
        
        //We process what remains in the stack as n (another unsigned binary integer)
        if(!stack.isEmpty()){
            System.out.println("decodeREAL(): Decoding n.");
            real.setN(decodeUnsignedBinaryInteger(stack));
            return real;
        }
        return null;
    }
    
    /** decodeUniversalTime() decodes the content into a UTCTime string.
     * 
     * @param content
     * @return UTCTime
     * @since 1.0
     */
    public String decodeUniversalTime(ASN1 content){
        //UniversalTime (UTCTime) has the universal tag 23
        //IMPLICIT
        //UniversalTime is represented as a VisibleString
        
        //Check for the VisibleString tag
        //System.out.println("decodeUniversalTime(): Method called.");
        //Two NOTES: 
        //The VisibleString is itself IMPLICIT to OCTET STRING, so if content is constructed then we fall to decoding a constructed OCTET STRING.
       
        //The UTCTime is IMPLICIT so the VisibleString tag is replaced with the UTCTime tag
        return decodeVisibleString(content);
    }
    
    /** decodeGeneralizedTime() decodes the content into a GeneralizedTime string.
     * 
     * @param content
     * @return GeneralizedTime 
     * @since 1.0
     */
    public String decodeGeneralizedTime(ASN1 content){
        //System.out.println("decodeGeneralizedTime(): Method called.");
        //GeneralizedTime has the universal tag 24
        //Generalized Time is represented as a VisibleString
        
        //Check for the VisibleString tag
        
        return decodeVisibleString(content.getItems().get(0));
    }
    
    /** decodeVisibleString() decodes the VisibleString object into a string.
     * 
     * @param content
     * @return VisibleString
     * @since 1.0
     */
    public String decodeVisibleString(ASN1 content){
        //VisibleString has the universal tag 26
        //It is IMPLICIT with OCTET STRING
        //It is constructed with an OCTET STRING
        //System.out.println("decodeVisibleString(): Method called.");
        if(content.getTag() == 26){
            //Its tag is explicitly defined so use constructed octet stream
            //byte[] cont = content.getItems().get(0).getContent();
            if(asnUtils.size(content) == 1){
                byte[] bytes = decodeConstructedOCTETSTRING(content.getItems().get(0).getItems());

                return new String(bytes, charset); //Change the charset
            }else{
                return "";
            }
        }else{
            //IMPLICIT and not constructed, directly decode.
            //byte[] cont = content.getItems().get(0).getContent();
            byte[] bytes = decodeOCTETSTRING(content.getContent());

            return new String(bytes, charset); //Change the charset
        }
        //return "";
    }
    
    //--------------------------------
    
    /** decodeShortBit() is used to decode the first five bits into a binary integer.
     *
     * @param b - The byte to decode
     * @return int - The decoded binary integer
     * @since 1.0
     * @tested - October 23, 2021
     */
    public int decodeShortBit(byte b){
        //We decode the first five bits and return an integer 32 or less
        //System.out.println("decodeShortBit(): Method called.");
        int integer = 0;
        for(int i = 0; i < 5 ; i++){
            if(mUtils.checkBit(b, i)){
                integer += Math.pow(2, i);
            }
        }  
        //System.out.println("decodeShortBit(): Integer " + integer + " decoded from byte " + b);
        return integer;
    } 
    
    /** decode7Bit decodes the byte's 7 bits into an integer.
     *
     * @param b - The byte to decode
     * @return The decoded integer
     * @since 1.0
     */
    public int decode7Bit(byte b){
        //System.out.println("decode7Bit(): Method called.");
        int integer = 0;
        for(int i = 0; i < 7; i++){
            if(mUtils.checkBit(b, i)){
                integer += Math.pow(2, i);
            }
        }
        return integer;
    }
    
    /** decodeIdentifierOctets() decodes the binary integer (tag) from the extra octets of the identifier.
     *
     * @param stack - The bytes to decode
     * @return int - The decoded binary integer.
     * @since 1.0
     * @tested October 23, 2021
     */
    public int decodeIdentifierOctets(Stack<Byte> stack){
        //System.out.println("decodeIdentifierOctets(): Method called.");
        //ArrayList<Integer> positions = new ArrayList<>();
        int integer = 0;
        int prior = 0;
        int count = 7;
        int index = 0; //index tracks the byte we are on.
        while(!stack.isEmpty()){
            //We start at the top of the stack.
            byte b = stack.pop();
            //System.out.println("decodeIdentifierOctets(): Processing byte " + b);
            for(int i = prior; i < count; i++){
                int position = (i % 8);  //isolates the bit position 0 - 7
                //System.out.println("decodeIdentifierOctets(): Working on the bit at position " + position + ".(0 - 7)");
                if(mUtils.checkBit(b, position)){                    
                    int real = i - index;
                    //System.out.println("decodeIdentifierOctets(): We have a bit at normal position " + i + ". The position for the bit in the "
                    //        + "binary integer is " + real);
                    integer += Math.pow(2, real);
                }
            }
            index++;
            prior = count + 1;  //The plus one skips the eight bit
            count += 8;
        }
        return integer;
    }
    
    /** decodeLengthOctets() decodes the extra octets in the length encoding. This is a simple decoding technique as all 8 bits are used.
     *
     * @param stack - The length octets to decode.
     * @return int - The decoded unsigned binary integer
     * @since 1.0
     * @tested October 24, 2021
     */
    public int decodeLengthOctets(Stack<Byte> stack){
        //System.out.println("decodeLengthOctets(): Method called.");
        int integer = 0;
        int count = 0;
        while(!stack.isEmpty()){
            byte b = stack.pop();
            for(int i = 0; i < 8; i++){
                if(mUtils.checkBit(b, i)){
                    integer += Math.pow(2, count);
                }
                count++;
            }
            //System.out.println("decodeLengthOctets(): Finished with byte " + b);
        }
        return integer;
    }
    
    /** decodeUnsignedBinaryInteger() is a helper method that converts the array to a stack, then uses decodeLengthOctets(). 
     * It decodes all 8 bits of each byte.
     *
     * @param bytes - The encoded unsigned integer
     * @return int - The decoded int
     * @since 1.0
     */
    public int decodeUnsignedBinaryInteger(byte[] bytes){
        //System.out.println("decodeUnsignedBinaryInteger(): Method called.");
        Stack<Byte> stack = new Stack<>();
        for(byte b : bytes){
            stack.add(b);
        }
        
        return decodeLengthOctets(stack);
    }
    
    /** decodeUnsignedBinaryInteger() decodes the stack of bytes into an unsigned binary integer.
     *
     * @param stack - The stack of bytes to decode
     * @return The unsigned binary integer
     * @since 1.0
     */
    public int decodeUnsignedBinaryInteger(Stack<Byte> stack){
        //System.out.println("decodeUnsignedBinaryInteger(): Method called.");
        return decodeLengthOctets(stack);
    }
}

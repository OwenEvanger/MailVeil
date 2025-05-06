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
 * This encoder class follows the X.208 and X.209 specifications for the Abstract Syntax Notation 1.
 * @author Owen
 */
public class ASNEncoder {
    Charset charset = Charset.forName("us-ascii");
    
    ByteArrayProcessor mProcessor = new ByteArrayProcessor();
    
    Utilities mUtils = new Utilities();
    
    public ASNEncoder(){
        
    }
    
    /** encodeUniversal() is used to encode the universal class objects. (DER compliant)
     * 
     * @param content - The content bytes
     * @param identifier - The identifier tag
     * @param constructed - Whether the object is constructed
     * @return byte[] - The encoded object
     * @since 1.0
    */
    public byte[] encodeUniversal(byte[] content, int identifier, boolean constructed){
        //System.out.println("encodeUniversal():  Method called.");
        ArrayList<byte[]> list = new ArrayList<>();
        
        //Step 1: Format the identifier octets.
        byte[] id = formatIdentifierOctets(identifier, true, false, false, false, constructed);
        list.add(id);
        
        //Step 2: Format the number of octets.
        int octets = content.length;
        byte[] length = formatLengthOctets(octets);
        list.add(length);
        
        //Step 3: Finally we add the contents.
        list.add(content);
        
        //Return the encoded integer
        return mProcessor.compileArrays(list); 
    }
    
    /** encodeContextSpecific() is used to encode context specific class objects.
     * 
     * @param content - The content bytes
     * @param identifier - The identifier tag
     * @param constructed - Whether the object is constructed
     * @return byte[] - The encoded object
     * @since 1.0 
     */
    public byte[] encodeContextSpecific(byte[] content, int identifier, boolean constructed){
        //System.out.println("encodeContextSpecific(): Method called.");
        ArrayList<byte[]> list = new ArrayList<>();
        
        //Step 1: Format the identifier octets.
        byte[] id = formatIdentifierOctets(identifier, false, false, true, false, constructed);
        list.add(id);
        
        //Step 2: Format the number of octets.
        int octets = content.length;
        byte[] length = formatLengthOctets(octets);
        list.add(length);
        
        //Step 3: Finally we add the contents.
        list.add(content);
        
        //Return the encoded integer
        return mProcessor.compileArrays(list);
    }
    
    //1
    /** encodeBoolean() encodes the primitive boolean type.
     *
     * @param yes The boolean value to encode
     * @return byte[] - The encoded object
     * @since 1.0
     * @tested October 24, 2021
     */
    public byte[] encodeBoolean(boolean yes){
        //Primitive type, number 1
        // contents : 0 = false; any value not 0 = true
        //System.out.println("encodeBoolean(): Method called.");
        if(yes){
            //System.out.println("encodeBoolean(): Encoding the TRUE value.");
            byte[] content = {1};
            return encodeUniversal(content, 1, false);
        }else{
            //System.out.println("encodeBoolean(): Encoding the FALSE value.");
            byte[] content = {0};
            return encodeUniversal(content, 1, false);
        }
    }
    
    //2
    /** encodeInteger() encodes the primitive ASN1 INTEGER type.
     *
     * @param integer - The integer to encode
     * @return byte[] - The encoded bytes
     * @since 1.0
     * @tested - October 25, 2021
     */
    public byte[] encodeInteger(int integer){
        //Integer is the universal tag 2 (primitive)
        //System.out.println("encodeInteger(): Method called.");
        //Format the contents of the INTEGER
        byte[] content = formatInteger(integer);
        
        return encodeUniversal(content, 2, false);        
    }
    
    //2
    /** encodeImplicitInteger() encodes the primitive ASN1 INTEGER type implicitly with the provided tag.
     *
     * @param integer - The integer to encode
     * @param tag - The identifier tag
     * @return byte[] - The encoded bytes
     * @since 1.0
     * @tested - October 25, 2021
     */
    public byte[] encodeImplicitInteger(int integer, int tag){
        //System.out.println("encodeImplicitInteger(): Method called.");
        //We replace the tag 2 with the provided tag, and set the context specific bit.
        byte[] content = formatInteger(integer);
        
        return encodeContextSpecific(content, tag, false);
    }
    
    //3
    //Primitive implementation
    /** encodeBitString() encodes the provided bitstring via the primitive specification. The first byte indicates the number of
     * trailing zeros in the final byte.
     *
     * @param bitstring - The provided bitstring, already formatted.
     * @param trailing_zeros - The trailing zeros (b/w 0 and 7)
     * @return byte[] - The encoded bitstring.
     * @since 1.0
     */
    public byte[] encodeBitString(byte[] bitstring, int trailing_zeros){
        //universal class, number 3
        //primitive or constructed
        //System.out.println("encodeBitString(): Method called.");
        ArrayList<byte[]> list = new ArrayList<>();
        
        if(trailing_zeros < 0 || trailing_zeros > 7){
            //System.out.println("encodeBitString(): Trailing zeros out of constraints.");
            return null;
        }
        //We encode the first octet as an unsigned binary integer constrained between 0 and 7
        byte[] first_octet = formatBinaryIntegerBasic(trailing_zeros); 
        list.add(first_octet);
        
        list.add(bitstring);
        
        return encodeUniversal(mProcessor.compileArrays(list), 3, false);
    }
    
    //3
    //Constructed implementation
    /** encodeConstructedBitString() encodes the list of partial bitstrings into a constructed bitstring. The trailing zeros are only applied
     * to the final part.
     *
     * @param list - The provided bitstrings, already formatted.
     * @param trailing_zeros - The trailing zeros (b/w 0 and 7)
     * @return byte[] - The encoded bitstring.
     * @since 1.0
     */
    public byte[] encodeConstructedBitString(ArrayList<byte[]> list, int trailing_zeros){
        //universal class, number 3
        //primitive or constructed
        System.out.println("encodeConstructedBitString(): Method called.");
        ArrayList<byte[]> results = new ArrayList<>();
        int count = 1;
        for(byte[] bytes : list){
            if(count == list.size()){
                System.out.println("encodeConstructedBitString(): On the last byte. Adding the trailing zeros.");
                //We add the trailing zeros
                results.add(encodeBitString(bytes, trailing_zeros));
            }else{
                System.out.println("encodeConstructedBitString(): On byte " + count);
                //We do not add any trailing zeros until the last part
                results.add(encodeBitString(bytes, 0));
            }
            count++;
        }
        return encodeUniversal(mProcessor.compileArrays(results), 3, true);
    }
    
    //4
    //Primitive
    /** encodeOctetString() is very basic. We do not even touch the bytes, just pass them to the universal method.
     *
     * @param values - The octet string
     * @return byte[] - The encoded octet string
     * @since 1.0
     */
    public byte[] encodeOctetString(byte[] values){
        //universal class, number 4
        //primitive or constructed
        //System.out.println("encodeOctetString(): Method called");
        return encodeUniversal(values, 4, false);
    }
    
    //4
    //Constructed
    /** encodeConstructedOctetString() is the implementation for a constructed octet string object.
     *
     * @param list - The list of octet strings to compile
     * @return byte[] - The encoded octet string
     * @since 1.0
     */
    public byte[] encodeConstructedOctetString(ArrayList<byte[]> list){
        //System.out.println("encodeConstructedOctetString(): Method called.");
        ArrayList<byte[]> results = new ArrayList<>();
        
        for(byte[] bytes : list){
            results.add(encodeOctetString(bytes));
        }
        return encodeUniversal(mProcessor.compileArrays(results), 4, true);
    }
    
    //4
    //PRIMITIVE - IMPLICIT
    /** encodeIMPLICITOctetString() encodes an octet string but replaces the octet string tag with the provided tag. 
     *
     * @param values - The array to encode
     * @param tag - The new tag for the octet string
     * @return byte[]
     * @since 1.0
     */
    public byte[] encodeIMPLICITOctetString(byte[] values, int tag){
        //System.out.println("encodeIMPLICITOctetString(): Method called.");
        return encodeContextSpecific(values, tag, false);
    }
    
    //5
    /** encodeNull() encodes the NULL ASN1 object.
     *
     * @return byte[] - The encoded NULL object.
     * @since 1.0
     */
    public byte[] encodeNull(){
        //System.out.println("encodeNull(): Method called.");
        //The NULL object has identifier 5 and length octet equal to 0 (ie. its a byte array with values 5 and 0).
        return new byte[]{5, 0};
    }
    
    //6
    /** encodeObjectIdentifier() encodes each id and compiles them into a series of octets.
     *
     * @param subs - The sub identifiers to encode
     * @return byte[] - The encoded object identifier
     * @since 1.0
     */
    public byte[] encodeObjectIdentifier(ArrayList<Integer> subs){
        //universal class, number 6
        //primitive
        //System.out.println("encodeObjectIdentifier(): Method called.");
        ArrayList<byte[]> list = new ArrayList<>();
        
        for(int sub : subs){
            list.add(formatObjectSubIdentifier(sub));
        }
        
        return encodeUniversal(mProcessor.compileArrays(list), 6, false);
    }
    
    //9
    /** encodeREALBinary encodes the real as specified in section 10.5. The general progression is to fill out the first byte, add the exponent's
     * encoding, and finally encode n.
     *
     * @param s - Either 1 or -1
     * @param n - The number to encode
     * @param b - The base
     * @param e - The exponent
     * @param f - The scaling factor
     * @return byte[] - The encoded real
     * @since 1.0
     */
    public byte[] encodeREALBinary(int s, int n, int b, int e, int f){
        //M*B ^ E
        System.out.println("encodeREALBinary(): Method called.");
        ArrayList<byte[]> results = new ArrayList<>();
        byte first = 0;
        first = mUtils.setBit(first, 7);
        
        //If s == -1 we set bit 7
        if(s == -1){
            System.out.println("encodeREALBinary(): s is -1, set bit 7 to 1.");
            first = mUtils.setBit(first, 6);
        }
        
        //Encode B
        System.out.println("encodeREALBinary(): Encoding the base.");
        if(b == 16){
            //base 16 - set bits 6 and 5 as 1 and 0.
            first = mUtils.setBit(first, 5);
        }else if(b == 8){
            //base 8 - set as 01
            first = mUtils.setBit(first, 4);
        }else{
            //base 2, leave as 00
        }
        
        //Encode F (value of 0 to 3)
        //Using bits 3 and 4 encode an unsigned binary integer
        System.out.println("encodeREALBinary(): Encoding the scaling factor.");
        if(f == 3){
            first = mUtils.setBit(first, 3);
            first = mUtils.setBit(first, 2);
        }else if(f == 2){
            first = mUtils.setBit(first, 3);
        }else if(f == 1){
            first = mUtils.setBit(first, 2);
        }else if(f == 0){
            //leave it
        }else{
            //error
            System.out.println("encodeREALBinary(): Error found in the scaling factor.");
            return null;
        }
        
        System.out.println("encodeREALBinary(): Determine how many octets are needed to encode the exponent, then format the exponent.");
        //Encode how many of the following octets encode E
        if(e <= 127 && e >= -128){
            //bits 2 and 1 are left as 00
            results.add(new byte[] {first});
            //encode e as a 2's complement number
            byte[] bytes = formatInteger(e);
            results.add(bytes);
        }else if((e >= 128 && e < 32768) || (e < -128 && e >= -32768)){
            //bits 2 and 1 are set to 01
            first = mUtils.setBit(first, 0);
            results.add(new byte[]{first});
            //encode e as a 2's complement number
            byte[] bytes = formatInteger(e);
            results.add(bytes);
        }else if((e >= 32768 && e < 8388608) || (e < -32768 && e > -8388608)){
            //bits 2 and 1 are set to 10
            first = mUtils.setBit(first, 1);
            results.add(new byte[]{first});
            //encode e as a 2's complement number
            byte[] bytes = formatInteger(e);
            results.add(bytes);
        }else{
            //Big exponent - set to 11
            first = mUtils.setBit(first, 1);
            first = mUtils.setBit(first, 0);
            results.add(new byte[]{first});
            
            //We format e first - 2's compl.
            byte[] bytes = formatInteger(e);
            
            //Next we encode the length of encoded e as an unsigned binary number
            byte[] length = formatBinaryIntegerBasic(bytes.length);
            if(length.length != 1){
                //error - too big
                System.out.println("encodeREALBinary(): The exponent is too large. Returning null.");
                return null;
            }
            results.add(length);
            results.add(bytes);
        }
        
        System.out.println("encodeREALBinary(): Encoding n.");
        //Finally, we encode N as an unsigned binary integer
        byte[] n_bytes = formatBinaryIntegerBasic(n);
        results.add(n_bytes);       
        
        return mProcessor.compileArrays(results);
    }
    
    //9
    /** encodeREALDecimal() encodes the already formatted ISO 6093 data.
     *
     * @param form - The specified form for the encoding.
     * @param content - The already formatted content.
     * @return byte[] - The encoded bytes.
     * @since 1.0
     */
    public byte[] encodeREALDecimal(String form, byte[] content){
        System.out.println("encodeREALDecimal(): Method called.");
        ArrayList<byte[]> list = new ArrayList<>();
        
        byte b = 0;
        //Bits 8 and 7 are set to 00
        
        //Next we determine the bits 6 to 1.
        switch(form){
            case "NR1":
                b = mUtils.setBit(b, 0);
                break;
                
            case "NR2":
                b = mUtils.setBit(b, 1);
                break;
                
            case "NR3":
                b = mUtils.setBit(b, 1);
                b = mUtils.setBit(b, 0);
                break;
                
            default:
                //Unrecognized
                System.out.println("encodeREALDecimal(): Encoding error. Unrecognized form.");
                return null;
        }
        list.add(new byte[]{b});
        list.add(content);
        
        return mProcessor.compileArrays(list);
    }
    
    //9
    /** encodeSpecialREALValue() is used to encode either positive or negative infinity.
     *
     * @param positive - Indicates whether it is positive or negative infinity.
     * @return byte[] - The encoded byte.
     * @since 1.0
     */
    public byte[] encodeSpecialREALValue(String positive){
        System.out.println("encodeSpecialREALValue(): Method called.");
        byte b = 0;
        //We set bit 7
        b = mUtils.setBit(b, 6);
        
        //We check if its negative infinity, if so we set bit 1
        if(!positive.equals("positive")){
            b = mUtils.setBit(b, 0);
        }
        //We return the one byte
        return new byte[]{b};
    }
       
    
    //10
    /** encodeEnumeratedType() encodes the list one integer at a time.
     * 
     * @param list - The list of integers
     * @return The encoded bytes.
     * @since 1.0
     */
    public byte[] encodeEnumeratedType(ArrayList<Integer> list){
        System.out.println("encodeEnumeratedType(): Method called.");
        //Universal class, number 10
        //We take the list of ids passed in and encode each.
        ArrayList<byte[]> results = new ArrayList<>();
        for(int i : list){
            results.add(encodeInteger(i));
        }
        
        //Now we have the contents encode
        byte[] res = mProcessor.compileArrays(results);
        
        return encodeUniversal(res, 10, false);
    }
        
    /** encodeCHOICE() simply leaves the encoded type and returns it.
     * 
     * @param bytes - The encoded type
     * @return The encoded bytes
     * @since 1.0
     */
    public byte[] encodeCHOICE(byte[] bytes){
        System.out.println("encodeCHOICE(): Method called.");
        //X.209 p.16
        //The encoding of a choice value shall be the same as the encoding of the selected value.
        return bytes;
    }
    
    /** encodeANY() leaves the encoding as it is and returns it.
     * 
     * @param bytes - The encoded type
     * @return The encoded bytes.
     * @since 1.0
     */
    public byte[] encodeANY(byte[] bytes){
        System.out.println("encodeANY(): Method called.");
        //X.209 p.17
        //Use the encoding of the value in the ANY type.
        return bytes;
    }
    
    /** encodeTag() encodes the tag in a general manner. The class and number are both provided as parameters.
     * 
     * @param bytes
     * @param clss
     * @param number
     * @return The encoded bytes.
     * @since 1.0
     */
    public byte[] encodeTag(byte[] bytes, int clss, int number){
        System.out.println("encodeTag(): Method called.");
        return bytes;
    }
    
    /** encodeExplicitTag() handles the situation where the EXPLICIT keyword appears in the syntax with a [tag]. The content passed
     * in has already been encoded, so we just wrap it up here.
     *
     * @param content - The content to wrap with the tag
     * @param tag - The explicit tag for the content.
     * @return byte[]
     * @since 1.0
     */
    public byte[] encodeExplicitTag(byte[] content, int tag){
        System.out.println("encodeExplicitTag(): Method called.");
        return encodeContextSpecific(content, tag, true);
    }
    
    /** encodeImplicitTag() is used by encoding methods to encode the implicit tag in place of what would otherwise be the normal tag.
     *
     * @param content - The base content
     * @param tag - The tag class number
     * @param constructed - Indicated if the base is itself constructed.
     * @return byte[] - The encoded contents
     * @since 1.0
     */
    public byte[] encodeImplicitTag(byte[] content, int tag, boolean constructed){
        System.out.println("encodeImplicitTag(): Method called.");
        return encodeContextSpecific(content, tag, constructed);
    }
    
    //16
    //Constructed type
    /** encodeSEQUENCE() encodes the data into a sequence.
     * 
     * @param content - The encoded sequence data
     * @return The encoded bytes
     * @since 1.0
     */
    public byte[] encodeSEQUENCE(byte[] content){ 
        //System.out.println("encodeSEQUENCE(): Method called.");
        return encodeUniversal(content, 16, true);
    }  
    
    //17
    //Constructed type
    /** encodeSETOF() encodes the data into a SETOF.
     * 
     * @param content - The encoded sequence data
     * @return The encoded bytes
     * @since 1.0 
     */
    public byte[] encodeSETOF(byte[] content){
        //System.out.println("encodeSETOF(): Method called.");
        return encodeUniversal(content, 17, true);
    }
    
    //18
    /** encodeNumericString() encodes the string.
     * 
     * @param string The string data
     * @return The encoded bytes
     * @since 1.0 
     */
    public byte[] encodeNumericString(String string){
        //NumericString has the universal tag 18 [IMPLICIT]
        return encodeIMPLICITOctetString(string.getBytes(charset), 18);
    }
    
    //19
    /** encodePrintableString() encodes the printable string data.
     * 
     * @param string The string data
     * @return The encoded bytes
     * @since 1.0 
     */
    public byte[] encodePrintableString(String string){
        System.out.println("encodePrintableString(): Method called.");
        //PrintableString has the universal tag 19 [IMPLICIT]
        //They are us-ascii encoded      A-Z, a-z, 0-9, '()+,-./:=?[space]
        return encodeIMPLICITOctetString(string.getBytes(charset), 19);
    }
    
    //20
    /** encodeTeletexString() encodes the teletex string data.
     * 
     * @param string The string data
     * @return The encoded bytes
     * @since 1.0 
     */
    public byte[] encodeTeletexString(String string){
        System.out.println("encodeTeletexString(): Method called.");
        //T61String (T.60 specification)
        //VideotexString has the universal tag 20 [IMPLICIT]
        return encodeIMPLICITOctetString(string.getBytes(charset), 20);
    }
    
    //21
    /** encodeVideotexString() encodes videotex string data.
     * 
     * @param string The string data
     * @return The encoded bytes
     * @since 1.0 
     */
    public byte[] encodeVideotexString(String string){
        System.out.println("encodeVideotexString(): Method called.");
        //VideotexString has the universal tag 21 [IMPLICIT]
        return encodeIMPLICITOctetString(string.getBytes(charset), 21);
    }
    
    //22
    /** encodeIA5String() encodes the IA5String data.
     * 
     * @param string The string data
     * @return The encoded bytes
     * @since 1.0 
     */
    public byte[] encodeIA5String(String string){
        System.out.println("encodeIA5String(): Method called.");
        //IA5String has the universal tag 22 [IMPLICIT]
        return encodeIMPLICITOctetString(string.getBytes(charset), 22);
    }
    
    //23
    /** encodeUTCTime() encodes the UTCTime
     * 
     * @param time The UTC time
     * @return The encoded bytes
     * @since 1.0 
     */
    public byte[] encodeUTCTime(String time){
        System.out.println("encodeUTCTime(): Method called.");
        //TESTED
        //UniversalTime (UTCTime) has the universal tag 23 [IMPLICIT]
        //UniversalTime is implicitly represented as a VisibleString which itself is implicitly represented as an octet string. Hence, we directly
        //call the implicit octet stream method.
        return encodeIMPLICITOctetString(time.getBytes(charset), 23);
    }
    
    //24
    /** encodeGeneralizedTime() encodes the generalized time.
     * 
     * @param time The generalized time
     * @return The encoded bytes
     * @since 1.0 
     */
    public byte[] encodeGeneralizedTime(String time){
        System.out.println("encodeGeneralizedTime(): Method called.");
        //GeneralizedTime has the universal tag 24 [IMPLICIT]
        //Generalized Time is represented as a VisibleString
        return encodeIMPLICITOctetString(time.getBytes(charset),24);
    }
    
    //25
    /** encodeGraphicString() encodes a graphic string.
     * 
     * @param string The string data
     * @return The encoded bytes
     * @since 1.0 
     */
    public byte[] encodeGraphicString(String string){
        System.out.println("encodeGraphicString(): Method called.");
        //GraphicString has the universal tag 25 [IMPLICIT]
        return encodeIMPLICITOctetString(string.getBytes(charset), 25);
    }
    
    //26
    /** encodeVisibleString() encodes a visible string.
     * 
     * @param string The string data
     * @return The encoded bytes
     * @since 1.0 
     */
    public byte[] encodeVisibleString(String string){
        System.out.println("encodeVisibleString(): Method called.");
        //VisibleString has the universal tag 26 [IMPLICIT]
        //It is constructed with an OCTET STRING
        return encodeIMPLICITOctetString(string.getBytes(charset), 26);
    }
    
    //27
    /** encodeGeneralString() encodes the general string.
     * 
     * @param string The string data
     * @return The encoded bytes
     * @since 1.0 
     */
    public byte[] encodeGeneralString(String string){
        System.out.println("encodeGeneralString(): Method called.");
        //GeneralString has the universal tag 27 [IMPLICIT]
        return encodeIMPLICITOctetString(string.getBytes(charset), 27);
    }
    
    
    
    //-------------------------- Formatting Code ---------------------------------//
    
    /** formatIdentifierOctets() fully encodes the ASN1 identifier, as specified in X.209.
     *
     * @param tag - The tag of the identifier
     * @param universal - class
     * @param application - class
     * @param context_specific - class
     * @param priv - class
     * @param constructed - Is the identifier for a constructed object, or a primitive object. True for constructed, false for primitive.
     * @return byte[] - The encoded identifier
     * @since 1.0
     * @tested - October 23, 2021
     */
    public byte[] formatIdentifierOctets(int tag, boolean universal, boolean application, boolean context_specific, boolean priv, 
            boolean constructed){
        //System.out.println("formatIdentifierOctets(): Method called.");
        byte b = 0;
        //Step 1: We start encoding the first byte.
        //Determine bits 7 and 8
        if(universal){
            //System.out.println("formatIdentifierOctets(): Universal class.");
            //00
        }else if(application){
            //System.out.println("formatIdentifierOctets(): Application class.");
            //01
            b = mUtils.setBit(b, 6);
        }else if(context_specific){
            //System.out.println("formatIdentifierOctets(): Context-Specific class.");
            //10
            b = mUtils.setBit(b, 7);
        }else{
            //System.out.println("formatIdentifierOctets(): Private class.");
            //Considered to be private
            //11
            b = mUtils.setBit(b, 7);
            b = mUtils.setBit(b, 6);
        }

        //Determine bit 6
        if(constructed){
            //System.out.println("formatIdentifierOctets(): Identifier is constructed.");
            //Bit 6 is set to 1
            b = mUtils.setBit(b, 5);
        }
        
        //Step 2: We continue depending on the size of the tag.
        if(tag < 31){  
            //System.out.println("formatIdentifierOctets(): Tag is less than 31, determining the bit positions for the tag.");
            //Determine the positions
            Stack<Integer> bits = determineBinaryIntegerBits(tag);
            
            //Set the final positions
            if(!bits.isEmpty()){
                for(int position : bits){
                    b = mUtils.setBit(b, position);
                }
            }
            //Return the encoded byte in an array
            return new byte[]{b};
        }else{
            //System.out.println("formatIdentifierOctets(): Tag size greater than or equal to 31, formatting the binary integer bytes.");
            //Two or more bytes are needed to encode this identifier
            ArrayList<byte[]> list = new ArrayList<>();
            
            byte[] bytes = formatBinaryInteger(tag);
            if(bytes != null){
                //System.out.println("formatIdentifierOctets(): Completing the first byte.");
                //We set the 5 positions all equal to 1
                
                for(int i = 0; i < 5; i++){
                    b = mUtils.setBit(b, i);
                }
                
                list.add(new byte[]{b});
                list.add(bytes);
                return mProcessor.compileArrays(list);
            }
        }
        System.out.println("formatIdentifierOctets(): Formatting error.");
        return null;
    }
    
    
    
    /** formatLengthOctets() is used to format the bytes encoding the number of octets in the contents. Both the short and long form are used.
     *
     * @param octets - The number of octets
     * @return byte[] - The formatted bytes
     * @since 1.0
     * @tested 
     */
    public byte[] formatLengthOctets(int octets){
        //We are encoding them as primitive
        //We try the short form first
        //System.out.println("formatLengthOctets(): Method called.");
        if(octets < 127){ 
            //System.out.println("formatLengthOctets(): The length is less than 127, hence we only encode one byte.");
            byte b = 0;
            //bit 8 is 0, bits 7 to 1 encode the number
            Stack<Integer> bits = determineBinaryIntegerBits(octets);
            for(int i : bits){
                b = mUtils.setBit(b, i);
            }
            //System.out.println("formatLengthOctets(): Byte encoded as " + b);
            byte[] bytes = new byte[]{b};
            
            return bytes;
        }else{
            //We use the long form
            byte[] bytes = formatBinaryIntegerBasic(octets);
            int length = bytes.length;
            //System.out.println("formatLengthOctets(): The number of bytes in the length encoding is " + length);
            byte b = 0;
            //Bits 1 to 7 encode the number of following octets holding the contents length.
            Stack<Integer> bits = determineBinaryIntegerBits(length);
            for(int i : bits){
                b = mUtils.setBit(b, i);
            }
            //System.out.println("formatLengthOctets(): Encoding the number of following bytes in the length encoding.");
            //Finally we set bit 8 to 1
            b = mUtils.setBit(b, 7);
            ArrayList<byte[]> list = new ArrayList<>();
            list.add(new byte[]{b});
            list.add(bytes);
            return mProcessor.compileArrays(list);
        }
    }
    
    /** formatInteger() formats the integer type. The integer is encoded as a 2s complement binary number using all 8 bits.
     *
     * @param integer - The integer to format
     * @return byte[] - The formatted bytes
     * @since 1.0
     */
    public byte[] formatInteger(int integer){
        //System.out.println("formatInteger(): Method called.");
        //System.out.println("formatInteger(): Encoding the integer " + integer);
        if(integer > 0){
            //We can use the formatBinaryIntegerBasic() method for this encoding
            //Ensure that if the most significant bit is set that a zero byte is appended to the front.
            return checkMostSignificantBit(formatBinaryIntegerBasic(integer));
        }else if(integer == 0){
            //We return a zero
            return new byte[]{(byte)0};
        }else{
            //We have a negative number
            return format2sComplementNegativeInteger(integer);
        }
    }
    
    /** formatObjectSubIdentifier() formats each integer as an unsigned binary number encoded with bits 7 to 1, and with the 8th bits
     * set to 1, except for the final octet.
     *
     * @param id - The sub identifier to encode
     * @return byte[] - The encoded sub identifier.
     * @since 1.0
     */
    public byte[] formatObjectSubIdentifier(int id){
        //The sub identifier is encoded exactly as layed out by formatBinaryInteger().
        //System.out.println("formatObjectSubIdentifier(): Method called.");
        return formatBinaryInteger(id);
    }
    
    
    
    
    /** formatBinaryInteger() follows the encoding specified for the Identifier Octets length component.
     *
     * @param integer - The integer we need to encode
     * @return byte[] - The encoded bytes, in order
     * @since 1.0
     * @tested - October 23, 2021
     */
    public byte[] formatBinaryInteger(int integer){
        //System.out.println("formatBinaryInteger(): Method called.");
        Stack<Integer> stack = determineBinaryIntegerBits(integer);
        //System.out.println("formatBinaryInteger(): The bit positions are : " + stack);
        Stack<Byte> results = new Stack<>();
        int count = 7;  //0-7 positions currently being processed
        byte cur = 0;
        int index = 0;
        
        while(true){
            //First we check to see if we have any remaining n's
            if(stack.isEmpty()){
                //System.out.println("formatBinaryInteger(): Stack has been fully processed.");
                //Add cur
                //We set bit 8 to 1
                cur = mUtils.setBit(cur, 7);
                byte b = (byte) cur;
                //System.out.println("formatBinaryInteger(): Adding the last byte " + b);
                results.add(0, b);
                break;
            }
            if(stack.peek() < count){  //change to <
                //We have a byte to encode               
                int position = stack.pop();
                //We then determine which bit n corresponds to
                //NOTE: The (7 + index) is used to account for the displacement caused by only being able to use 7 of the 8 bits. This increases by
                //1 for each byte we process. Its a count of the offset.
                int location = (7 + index) - (count - position); //The 7 minus flips the index
                //System.out.println("formatBinaryInteger(): Setting the position " + position + " at " + location);
                //cur += 2 ^ (location - 1); //Switch to the index position (ie. bit 7 is 2 ^ 6).
                cur = mUtils.setBit(cur, location);               
            }else{
                //We increment count and then try again
                //System.out.println("formatBinaryInteger(): Finished with the byte. Incrementing count. Setting bit 8, then adding cur to the results.");
                count += 8;
                index++;
                //Wrap up bit 8
                cur = mUtils.setBit(cur, 7);
                byte b = (byte) cur;
                results.add(0, b);
                
                //Reset cur
                cur = 0;                
            }
        }
        if(!results.isEmpty()){
            //We need to set bit 8 of the last octet to 0
            byte b = results.pop(); 
            //System.out.println("formatBinaryInteger(): Unsetting bit 8 of the last octet in the stack " + b);
            b = mUtils.setBitToZero(b, 7);
            //System.out.println("formatBinaryInteger(): Unset byte is " + b);
            //Push it back onto the stack.
            results.push(b);
            
            //System.out.println("formatBinaryInteger(): Final results are : " + results);
            return mUtils.compile(results);
        }
        
        return null;
    }
    
    /** formatBinaryIntegerBasic() is used to encode the number of octets for the length component. It uses all 8 bits.
     *
     * @param octets - The number of octets
     * @return byte[] - The formatted bytes
     * @since 1.0
     * @tested - October 24, 2021
     */
    public byte[] formatBinaryIntegerBasic(int octets){
        //System.out.println("formatBinaryIntegerBasic(): Method called.");
        //Determine the bits that need to be set to 1.
        Stack<Integer> stack = determineBinaryIntegerBits(octets);
        Stack<Byte> results = new Stack<>();
        byte cur = 0;
        int count = 7;
        while(true){
            //First we check to see if we have any remaining n's
            if(stack.isEmpty()){
                //System.out.println("formatBinaryIntegerBasic(): Stack has been fully processed.");
                //Add cur
                //We set bit 8 to 1
                //cur = mUtils.setBit(cur, 7);
                byte b = (byte) cur;
                //System.out.println("formatBinaryIntegerBasic(): Adding the last byte " + b);
                results.add(0, b);
                break;
            }
            if(stack.peek() <= count){ 
                //We have a byte to encode               
                int position = stack.pop();
                //We then determine which bit n corresponds to
                //NOTE:
                
                int location = position % 8; //We use all 8 bits
                //System.out.println("formatBinaryIntegerBasic(): Setting the position " + position + " at " + location);
                //cur += 2 ^ (location - 1); //Switch to the index position (ie. bit 7 is 2 ^ 6).
                cur = mUtils.setBit(cur, location);               
            }else{
                //We increment count and then try again
                //System.out.println("formatBinaryIntegerBasic(): Finished with the byte. Incrementing count. Setting bit 8, then adding cur to the results.");
                count += 8;
                
                byte b = (byte) cur;
                results.add(0, b);
                
                //Reset cur
                cur = 0;                
            }
        }
        if(!results.isEmpty()){
            return mUtils.compile(results);
        }
        return null;
    }
    
    /** format2sComplementNegativeInteger()  formats the integer to 2s complement.
     *
     * @param integer - The negative integer
     * @return byte[] The encoded bytes
     * @since 1.0
     */
    public byte[] format2sComplementNegativeInteger(int integer){
        //System.out.println("format2sComplementNegativeInteger(): Method called.");
        
        byte[] pre = formatBinaryIntegerBasic(Math.abs(integer));
        //We need to check if the most significant bit is set to 1, if so we add a 0 byte before converting it to 2s complement.
        byte[] post = checkMostSignificantBit(pre);
        
        return mUtils.convert2sComplement(post);
    }
    
    /** determineBinaryIntegerBits() goal is to determine the bits set to 1 in a binary representation of the integer. The resulting
     * stack will note each position that contains a 1. This is a convenience method used when encoding a binary integer.
     *
     * @param integer - The integer to process
     * @return The resulting positions
     * @since 1.0
     */
    public Stack<Integer> determineBinaryIntegerBits(int integer){
        //System.out.println("determineBinaryIntegerBits(): Method called.");
        Stack<Integer> stack = new Stack<>();
        //Initialize our remainder
        int remainder = integer;
        
        //Our goal is to determine each bit position that contains a 1.
        while(remainder != 0){
            //We need to find the highest (2 ^ n) that comes in just at or under the remainder.
            for(int n = 0;; n++){ //We do not constrain n as we do not know how high we may need to go.
                if((remainder < (Math.pow(2, n + 1)))){
                    //If what remains is less than the next 2 ^ n then we have found the highest n.
                    stack.add(n);
                    //Decrement the remainder
                    remainder -= (Math.pow(2, n));
                    //Exit the for statement
                    break;
                }
            }
        }
        return stack;
    }
    
    /** checkMostSignificantBit() checks the first byte in the array and sees if bit 8 is set. If so we need to add a 0 byte in front of it
     * before we use the conversion algorithm.
     *
     * @param bytes
     * @return The finished bytes
     * @since 1.0
     */
    public byte[] checkMostSignificantBit(byte[] bytes){
        //System.out.println("checkMostSignificantBit(): Method called.");
        if(bytes == null || bytes.length == 0){
            return null;
        }
        byte b = bytes[0];
        if(mUtils.checkBit(b, 7)){
            byte[] new_array = new byte[]{0};
            ArrayList<byte[]> list = new ArrayList<>();
            list.add(new_array);
            list.add(bytes);
            return mProcessor.compileArrays(list);
        }
        return bytes;
    }
}

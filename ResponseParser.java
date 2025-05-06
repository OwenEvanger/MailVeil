/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package SMTP.Parsing;

import Parresia.ParsingResult;
import Parsing.RFC5322Parsing;
import Parsing.SMTPParsing;
import SMTP.SMTPExtension;
import SMTP.SMTPResponse;
import Utilities.Utilities;
import java.nio.charset.Charset;
import java.util.Stack;

/**
 *
 * @author Owen
 */
public class ResponseParser {
    Charset charset = Charset.forName("us-ascii");
    
    RFC5322Parsing mFieldParser = new RFC5322Parsing();
    
    SMTPParsing mSMTPParser = new SMTPParsing();
    
    SMTPResponse response = new SMTPResponse();
        
    SMTPExtension extension = new SMTPExtension();
    
    Utilities mUtils = new Utilities();

    Stack<Byte> stack = new Stack<>();

    //NOTE: The states maintain the state within the line itself and the line relative to the other lines. (ie. parsing the code on the first line)
    boolean first_line_state = true;
    boolean code_state = true;  //We parse the code while in this state.
    boolean domain_state = false;
    boolean textstring_state = false;
    boolean last_line_state = false; //Both the first and last line states may be true at the same time.
    boolean ehlo_keyword_state = true;
    boolean ehlo_param_state = false;
    
    boolean line_end = false;
    
    public ResponseParser(){
        
    }
    
    /** parseSMTPServerResponse() handles the potentially multiline command response from an SMTP server. It breaks the response down and fills
     * a SMTPResponse object. If an error is encountered while parsing that is saved in the SMTPResponse, as well as a description of the error and 
     * its cause. The object would then be returned. Context is used while parsing so that extensions and their params can be elegantly handled.
     *
     * @param bytes - The response
     * @param greeting - If it is a greeting response 
     * @param ehlo_greeting - If it is an extended ehlo response
     * @return SMTPResponse - The response validated and extracted.
     * @since 1.0
     */
    public ParsingResult parseSMTPServerResponse(byte[] bytes, boolean greeting, boolean ehlo_greeting){
        //System.out.println("parseSMTPServerResponse(): Method called.");
        //This is client side parsing of a response from an SMTP host server.
        //We anticipate the potential for multiple lines, though realistically only a few command responses will send multiple lines. So that 
        //being said the parsing ends when all bytes have been exhausted.
       
        for(int i = 0; i < bytes.length; i++){
            byte b = bytes[i];
            if(line_end){
                stack.add(b);
                if(stack.size() == 2){
                    if(stack.pop() == 10 && stack.pop() == 13){
                        if(last_line_state){
                            //We are done
                            response.setComplete();
                            return mUtils.parsingSuccess(i, response);
                        }
                        line_end = false;
                    }else{
                        response.setError();
                        response.setErrorDescription("CRLF was expected.");
                        return mUtils.parsingFailure(response, b);
                    }
                }
            }else if(code_state){
                if(b == 32 || b == 45 || b == 13){  //Space, hyphen or CRLF
                    //System.out.println("parseSMTPServerResponse(): Parsing the response code.");
                    //This is the last line
                    if(stack.isEmpty()){
                        response.setError();
                        response.setErrorDescription("Stack was empty when trying to validate response code.");
                        return mUtils.parsingFailure(response, b);
                    }
                    int counter = 0;
                    for(byte item : stack){
                        if(counter > 2){
                            break;
                        }
                        switch (counter) {
                            case 0:
                                //first digit of the reply code must be b/w bytes 50 - 53 (inclusive)
                                if(item < 50 || item > 53){
                                    response.setError();
                                    response.setErrorDescription("Digit one of the response code falls outside the specification");
                                    return mUtils.parsingFailure(response, i);
                                }   break;
                            case 1:
                                //second digit must be b/w bytes 48 - 53 (inclusive)
                                if(item < 48 || item > 53){
                                    response.setError();
                                    response.setErrorDescription("Digit two of the response code falls outside the specification");
                                    return mUtils.parsingFailure(response, i);
                                }   break;
                            case 2:
                                //third digit of the reply code must be b/w bytes 48 - 57 (inclusive)
                                if(item < 48 || item > 57){
                                    response.setError();
                                    response.setErrorDescription("Digit three of the response code falls outside the specification");
                                    return mUtils.parsingFailure(response, i);
                                }   break;
                            default:
                                break;
                        }                        
                        counter++;
                    }
                    //System.out.println("parseSMTPServerResponse(): Digits of the response code were validated.");
                    byte[] stack_bytes = mUtils.compile(stack);
                    stack.clear();
                    //Check the code
                    String code = new String(stack_bytes, charset);
                    //temporary.put("RESPONSECODE", code);
                    response.setCode(code);
                    //Nothing comes after the response code so we consider the response complete.
                    //FUTURE: This can be expanded...
                    if(b == 13){
                        //Add to results and return
                        //results.put("LINE1", temporary);
                        //return results;
                        //System.out.println("parseSMTPServerResponse(): CR found immediately after response code. Returning the response.");
                        last_line_state = true;
                        line_end = true;
                        stack.add(b);
                        //return mUtils.parsingSuccess(i + 1, response);  //Move to the LF position
                    }else{
                    
                        //We see if we are expecting a domain next
                        if((greeting || ehlo_greeting) && first_line_state){
                            //System.out.println("parseSMTPServerResponse(): Moving from the code state to the domain state.");
                            domain_state = true;
                            ehlo_keyword_state = false;
                        }else if(ehlo_greeting){
                            //We expect the keyword immediately after the code
                            //System.out.println("parseSMTPServerResponse(): Moving from the code state to the ehlo keyword state.");
                            ehlo_keyword_state = true;
                        }

                        //Appearance of a WS following the code indicates that this is the last line of a multiline response.
                        if(b == 32){
                            //System.out.println("parseSMTPServerResponse(): Whitespace found immediately after the response code. Moved to last line state.");
                            last_line_state = true;
                            //temporary.put("LASTLINE", "TRUE");
                        }
                    }
                    //We are no longer in the code state
                    code_state = false;
                    
                    //textstring_state = true;  //?
                }else{
                    stack.add(b);
                }
            }else{  //code_state
                //System.out.println("Finished with the code.");
                if(domain_state){
                    //We extract a domain / address-literal
                    if(b == 32 || b == 13){  //SP
                        if(!stack.isEmpty()){
                            //Process the stack
                            //System.out.println("parseSMTPServerResponse(): Validating the domain in the domain state.");
                            byte[] stack_bytes = mUtils.compile(stack);                            
                            stack.clear();
                            String domain = new String(stack_bytes, charset);
                            //Validate the domain
                            if(mFieldParser.checkDomain(domain)){
                                //System.out.println("parseSMTPServerResponse(): Domain has been validated in the domain state.");
                                response.setDomain(domain);
                                //temporary.put("DOMAIN", domain);
                                if(b == 13){
                                    //We have reached the CR of the final line
                                    if(last_line_state){
                                        //We return
                                        //results.put("LINE" + linecount, temporary);
                                        line_end = true;
                                        //return mUtils.parsingSuccess(i, response);
                                        //return results;
                                    }else{
                                        if(first_line_state){
                                            first_line_state = false;
                                        }
                                    }
                                }else{
                                    //We have a WS so we next expect textstring.
                                    textstring_state = true;
                                }
                            }else{
                                response.setError();
                                response.setErrorDescription("Domain validation failed in the domain state. Domain was " + domain);
                                return mUtils.parsingFailure(response, i);
                            }
                        }else{
                            response.setError();
                            response.setErrorDescription("Stack was found to be empty when checking for the domain.");
                            return mUtils.parsingFailure(response, i);
                        }
                        domain_state = false;
                    }else{
                        stack.add(b);
                    }
                }else{  //domain_state
                    //We store the bytes until we reach the CR token.
                    if(b == 13){  //CR
                        //Wrap up the line
                        if(!stack.isEmpty()){
                            //Process the stack
                            byte[] stack_bytes = mUtils.compile(stack);
                            //System.out.println("Stack size is " + stack.size());
                            
                            //We check our context to see how to process the remainder of the response line
                            if(!ehlo_greeting){
                                //System.out.println("parseSMTPServerResponse(): Validating the textstring.");
                                if(mSMTPParser.checkTextString(stack_bytes)){
                                    //System.out.println("parseSMTPServerResponse(): Textstring was validated.");
                                    String string = new String(stack_bytes, charset);
                                    response.addText(string);
                                    
                                    
                                    //temporary.put("TEXTSTRING", string);                                  
                                } //else we just drop it
                                line_end = true;
                            }else{
                                //We handle the ehlo spec
                                if(first_line_state){
                                    //In the first line we have text following the code
                                    if(mSMTPParser.checkTextString(stack_bytes)){
                                        String string = new String(stack_bytes, charset);
                                        //System.out.println("parseSMTPServerResponse(): Textstring was validated: " + string);
                                        response.addText(string);
                                        //temporary.put("TEXTSTRING", string);                                  
                                    } 
                                    stack.clear();
                                    first_line_state = false;
                                }else{
                                    //We are at the end of one of the lines of a multiline response in the context of an EHLO response.
                                    //We either have a solitary keyword or we are on a param.
                                    if(ehlo_keyword_state){
                                        String keyword = new String(stack_bytes, charset);
                                        //System.out.println("parseSMTPServerResponse(): Validating the EHLO keyword " + keyword + " in the ehlo"
                                        //        + " keyword state.");
                                        if(mSMTPParser.checkEHLOKeyword(stack_bytes)){
                                            //We hold the extension
                                            //extension = new String(stack_bytes, charset);
                                            extension.setName(new String(stack_bytes, charset));
                                            SMTPExtension copy = extension;
                                            response.addExtension(copy);
                                            extension = new SMTPExtension();
                                            //System.out.println("parseSMTPServerResponse(): EHLO keyword was validated.");
                                            //response.addText(keyword);
                                            //temporary.put(keyword, keyword);                                          
                                        }else{
                                            //Fatal error
                                            response.setError();
                                            response.setErrorDescription("EHLO keyword was not validated. EHLO = " + extension);
                                            return mUtils.parsingFailure(response, i);
                                        }
                                    }else{
                                        //We treat this as an EHLO parameter
                                        String param = new String(stack_bytes, charset);
                                        //System.out.println("parseSMTPServerResponse(): Validating the EHLO param = " + param);
                                        if(mSMTPParser.checkEHLOParam(stack_bytes)){                                                                                       
                                            //Add the parameter
                                            //params.add(param);
                                            extension.addParam(param);
                                            //System.out.println("parseSMTPServerResponse(): EHLO param was validated.");
                                            //As we are at a CR we consider the line to be done so we add the extension and params
                                            SMTPExtension copy = extension;
                                            response.addExtension(copy);
                                            //Clear the holder variables
                                            extension = new SMTPExtension();
                                            //params = new ArrayList<>();                                       
                                        }else{
                                            //Fatal error
                                            response.setError();
                                            response.setErrorDescription("EHLO param was not validated. Param = " + param);
                                            return mUtils.parsingFailure(b, i);
                                        }
                                    }
                                }
                            }
                            stack.clear();
                        }
                        //As we are at a CR we close out the line, and reinitialize the states.
                        first_line_state = false;
                        line_end = true;
                        code_state = true;
                        //ehlo_keyword_state = true;  //?
                        ehlo_param_state = false;
                        textstring_state = false;
                        stack.add(b);
                    }else if(b == 32){
                        if(ehlo_greeting && !first_line_state){
                            //Process the stack
                            if(!stack.isEmpty()){
                                byte[] stack_bytes = mUtils.compile(stack);
                                stack.clear();

                                if(ehlo_keyword_state){
                                    String keyword = new String(stack_bytes, charset);
                                    //System.out.println("parseSMTPServerResponse(): Validating the EHLO keyword " + keyword + " in the ehlo"
                                    //            + " keyword state.");
                                    if(mSMTPParser.checkEHLOKeyword(stack_bytes)){
                                        //System.out.println("parseSMTPServerResponse(): EHLO keyword was validated.");
                                        //extension = new String(stack_bytes, charset);
                                        extension.setName(new String(stack_bytes, charset));
                                        //ehlo_stack.add(keyword);
                                    }else{
                                        //Fatal error
                                        response.setError();
                                        response.setErrorDescription("EHLO keyword was not validated. EHLO = " + extension);
                                        return mUtils.parsingFailure(response, i);
                                    }
                                    ehlo_keyword_state = false;
                                    ehlo_param_state = true;
                                }else if(textstring_state){
                                    //We hold the whitespace
                                    stack.add(b);
                                }else{
                                    String param = new String(stack_bytes, charset);
                                    //System.out.println("parseSMTPServerResponse(): Validating the EHLO param = " + param);
                                    if(mSMTPParser.checkEHLOParam(stack_bytes)){                                       
                                        //params.add(param);
                                        extension.addParam(param);
                                        //temporary.put(ehlo_stack.pop(), param);
                                        //ehlo_stack.clear();
                                        //System.out.println("parseSMTPServerResponse(): EHLO param was validated.");
                                    }else{
                                        //Fatal error
                                        response.setError();
                                        response.setErrorDescription("EHLO param was not validated. Param = " + param);
                                        return mUtils.parsingFailure(response, i);
                                    }
                                }
                            }//We ignore an empty stack here
                        }else{
                            stack.add(b);
                        }
                    }else{
                        stack.add(b);
                    }
                }
            }
        }
        System.out.println("parseSMTPServerResponse(): Response not finished. More bytes needed to finish parsing.");
        return new ParsingResult();
    }
}

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package IMAP.Sessions;

import IMAP.Parsing.MailboxParser;
import IMAP.Parsing.MsgAttParsing;
import IMAP.Parsing.RespCondStateParser;
import IMAP.Parsing.RespTextParser;
import IMAP.Parsing.ResponseDataParser;
import IMAP.Parsing.ResponseParser;
import IMAP.Structures.IMAPContinuationRequest;
import IMAP.Structures.IMAPContinueReq;
import IMAP.Structures.IMAPGreeting;
import IMAP.Structures.IMAPMailboxData;
import IMAP.Structures.IMAPMailboxList;
import IMAP.Structures.IMAPMessageData;
import IMAP.Structures.IMAPMsgAtt;
import IMAP.Structures.IMAPResponse;
import IMAP.Structures.IMAPResponseConditionState;
import IMAP.Structures.IMAPResponseData;
import IMAP.Structures.IMAPResponseDone;
import IMAP.Structures.IMAPResponseFatal;
import IMAP.Structures.IMAPResponseTagged;
import IMAP.Structures.IMAPResponseText;
import Parresia.ParsingResult;
import Parsing.IMAPParsing;
import Utilities.Utilities;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Stack;


/**
 *
 * @author Owen
 */
public class IMAPResponseParser {
    ArrayList<Object> lines = new ArrayList<>();
    
    Charset charset = Charset.forName("us-ascii");
    
    //Holds the overall fetch response
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    
    Utilities mUtils = new Utilities();
    
    IMAPParsing mIMAPParser = new IMAPParsing();
    
    Stack<Byte> stack = new Stack<>();
    
    
    IMAPResponse response = new IMAPResponse();
    
    IMAPGreeting greeting = new IMAPGreeting();
    
    ResponseParser responseParser = new ResponseParser();
    
    MsgAttParsing attributeParser = new MsgAttParsing();
    
    boolean prelude = true;
    
    //fetch() 
    //The first atom of a line
    boolean line_prelude = true;
    
    boolean line = false;
    
    boolean line_check = false;
    
    boolean response_done_line = false;
    
    boolean end_of_line = false;
    
    //Complete is set to true when the end line is reached.
    boolean complete = false;
    
    boolean error = false;
    
    RespTextParser responseTextParser = new RespTextParser();
    
    //response-data line
    boolean response_date = false;
    
    //response-done line
    boolean response_done = false;
    
    //The parsing state (ie. fetch, capability, etc.)
    String state = new String();
    
    //The expected linecode
    String linecode = new String();
    
    
    //--------------- continue-req methods --------------------//
    boolean continue_request = false;
    
    //--------------- response-done methods -------------------//
    IMAPResponseTagged tagged_response = new IMAPResponseTagged();
    
    RespCondStateParser responseCondParser = new RespCondStateParser();
    
    boolean resp_tagged = false;
    
    boolean fatal = false;
    
    
    //--------------- resp-cond-state methods ----------------//
    IMAPResponseConditionState condition_state = new IMAPResponseConditionState();
    
    boolean resp_cond_state = false;
    
    
    //--------------- mailbox-data methods -------------------//
    IMAPMailboxData data = new IMAPMailboxData();
    
    MailboxParser mailboxParser = new MailboxParser();
    
    Stack<Integer> number_stack = new Stack<>();
    
    boolean flags = false;
    
    boolean flag_list = false;
    
    boolean mailbox_list = false;
    
    
    boolean search = false;
    
    boolean nznumbers = false;  // *(SP nz-number)
    
    boolean status = false;
    
    boolean status_mailbox = false;
    
    boolean status_list = false;
    
    boolean status_list_att = false;
    
    ResponseDataParser dataParser = new ResponseDataParser();
    
    boolean capability = false;
    
    //Handles the CAPABILITY response inside mailbox-data
    boolean capability_mailbox_data = false;
    
    boolean number = false;
    
    //---------------- Message Data Methods --------------//
    IMAPMessageData msg = new IMAPMessageData();
    
    boolean fetch = false;
    
    
    //Used to determine the type of response-data
    boolean untagged = false;
    
    boolean space = false;
    
    boolean line_end = false;  
    
    public IMAPResponseParser(String linecode, String state){
        this.state = state;
        this.linecode = linecode;
    }
    
    /** parse() parses the server response to any IMAP command. As each buffer is read in it is passed to this resilient parser and the 
     * results are stored until the end of the response as defined in the specification.
     * 
     * Any remaining data in the buffer may be cleared.
     * 
     * @param buffer - The input buffer to parse
     * @param linecode - The expected linecode to receive
     * @param greet - Tells the parser that we expect the greeting structure, not a response.
     * @return ParsingResult - The result of the parse() call. If complete an IMAPResponse object will be stored in it.
     */
    public ParsingResult parse(byte[] buffer, String linecode, boolean greet){
        System.out.println("parse(): Method called.");
        //RFC 5301 p.88
        //response = *(continue-req / response-data) response-done
        
        //Our first task is to identify which of the three possible responses we are handling. We do this in the prelude state.
        for(int i = 0; i < buffer.length; i++){
            byte b = buffer[i];
            
            if(line_end){
                stack.add(b);
                if(stack.size() == 2){
                    //Ensure we have CR and LF
                    byte[] stack_bytes = mUtils.compile(stack);
                    //System.out.println("parse(): Bytes in line_end are: " + stack_bytes[0] + " " + stack_bytes[1]);
                    if((!(stack.pop() == 10)) && (!(stack.pop() == 13))){
                        System.out.println("parse(): CRLF was expected in line_end.");
                        return mUtils.parsingFailure(i);
                    }
                    if(greet || continue_request){
                        //Return the response
                        return mUtils.parsingSuccess(i, response);
                    }
                    stack.clear();
                    line_end = false;
                }
                
            }else if(prelude){
                if(b == 32){
                    if(!stack.isEmpty()){
                        byte[] stack_bytes = mUtils.compile(stack);
                        String start = new String(stack_bytes, charset);
                        //System.out.println("parse(): Handling the prelude: " + start);
                        stack.clear();
                        if(start.equals(linecode)){
                            //We have a response-tagged line for response-done.
                            //System.out.println("parse(): Setting the tag: " + start);
                            tagged_response.setTag(start);
                            resp_tagged = true;
                           
                        }else if(start.equals("*")){
                            //We need to see what the next argument is before we handle it.
                            //Check for BYE -> fatal
                            //System.out.println("parse(): We have an untagged response line.");
                            untagged = true;
                        }else if(start.equals("+")){
                            //We have a continuation request
                            continue_request = true;
                        }else{
                            //System.out.println("parse(): Erroneous prelude.");
                            return mUtils.parsingFailure(i);
                        }                        
                        prelude = false;
                    }else{
                        //System.out.println("parse(): Empty stack in prelude.");
                        return mUtils.parsingFailure(i);
                    }
                }else{
                    stack.add(b);
                }
            }else if(untagged){
                //We collect bytes until we reach the SP token, then we determine what type of untagged response we have.
                //NOTE: In the case of the empty SEARCH result we look for a CRLF
                if(b == 32 || b == 13){  //BUG FIX
                    if(stack.isEmpty()){
                        //System.out.println("parse(): Empty stack in untagged.");
                        return mUtils.parsingFailure(i);
                    }
                    byte[] stack_bytes = mUtils.compile(stack);
                    String arg = new String(stack_bytes, charset);
                    //System.out.println("parse(): Received the condition " + arg + " in untagged.");
                    if(arg.equals("OK") || arg.equals("NO") || arg.equals("BAD")){
                        //We have the resp-cond-state
                        //resp-cond-state = ("OK" / "NO" / "BAD") SP resp-text
                        condition_state.setStatus(arg); //Set the state
                        resp_cond_state = true;
                        if(greet){
                            //TESTED
                            //System.out.println("parse(): Setting the greeting condition.");
                            greeting.setCondition(arg);
                        }
                    }else if(arg.equals("PREAUTH")){
                        greeting.setCondition(arg);
                        resp_cond_state = true;
                    }else if(arg.equals("BYE")){
                        //resp-cond-bye = "BYE" SP resp-text
                        if(greet){
                            greeting.setCondition(arg);
                        }
                        fatal = true;
                    }else if(arg.equals("FLAGS")){
                        //mailbox-data
                        //"FLAGS" SP flag-list CRLF
                        data.setType("FLAGS");
                        flag_list = true;
                    }else if(arg.equals("LIST") || arg.equals("LSUB")){
                        //mailbox-list
                        data.setType(arg);
                        mailbox_list = true;
                    }else if(arg.equals("SEARCH")){
                        //*(SP nz-number)
                        data.setType(arg);

                        if(b == 13){
                            //No SEARCH results
                            stack.clear();
                            IMAPMailboxData copy = data;
                            data = new IMAPMailboxData();
                            IMAPResponseData dat = new IMAPResponseData();
                            dat.setType("mailbox-data");
                            dat.setData(copy);
                            response.addResponseData(dat);
                            line_end = true;
                            prelude = true;
                            stack.add(b);
                        }else {
                            search = true;
                            nznumbers = true;
                        }
                    }else if(arg.equals("STATUS")){
                        data.setType(arg);
                        status = true;
                        status_mailbox = true;
                        
                    }else if(arg.equals("CAPABILITY")){
                        //TESTED
                        capability = true;
                    }else{
                        //We check for a number. This could mean we have either the EXISTS or RECENT kewords next or if its a nonzero
                        //number we may have message-data.
                        if(mIMAPParser.validateNumber(stack_bytes)){
                            //Add to the number stack (exists, recent, msn...)
                            int num = Integer.parseInt(new String(stack_bytes, charset));
                            number_stack.add(num);
                            number = true;
                        }else{
                            //System.out.println("parse(): Unknown type of untagged response.");
                            return mUtils.parsingFailure(i);
                        }
                    }
                    untagged = false;
                    if(b != 13) {
                        stack.clear();
                    }
                }else{
                    stack.add(b);
                }
            }else if(resp_tagged){
                ParsingResult res = responseParser.parseResponseTagged(buffer, i);
                if(!res.isSuccess()){
                    //System.out.println("parse(): Parsing failed in resp_tagged.");
                    return mUtils.parsingFailure(i);
                }
                if(res.isComplete()){
                    IMAPResponseTagged tagged = (IMAPResponseTagged) res.getObject();
                    //We take the linecode directly from the params
                    tagged.setTag(linecode); 
                    IMAPResponseDone done = new IMAPResponseDone();
                    done.setDone(tagged);
                    response.setResponseDone(done);
                    i = res.getIndex();
                    //We are finished...
                    return mUtils.parsingSuccess(i, response);
                }
                i = buffer.length;
            }else if(fatal){
                //response-fatal = "*" SP resp-cond-bye CRLF
                //resp-cond-bye = "BYE" SP resp-text
                //We start at the resp-text of resp-cond-bye
                ParsingResult res = responseTextParser.parseRespText(buffer, i);
                if(!res.isSuccess()){
                    //System.out.println("parse(): Parsing failed in fatal.");
                    return mUtils.parsingFailure(i);
                }
                if(res.isComplete()){
                    //We are done...
                    IMAPResponseText text = (IMAPResponseText) res.getObject();
                    IMAPResponseFatal response_fatal = new IMAPResponseFatal();
                    response_fatal.setResponseText(text);
                    responseTextParser = new RespTextParser(); //Refresh the parser
                    IMAPResponseDone done = new IMAPResponseDone();
                    done.setDone(response_fatal);
                    response.setResponseDone(done);
                    i = res.getIndex();
                    //We are finished...
                    return mUtils.parsingSuccess(i, response);
                }
                i = buffer.length;
            }else if(resp_cond_state){
                ParsingResult res = responseTextParser.parseRespText(buffer, i);
                if(!res.isSuccess()){
                    //System.out.println("parse(): Parsing failed in resp_cond_state.");
                    return mUtils.parsingFailure(i);
                }
                if(res.isComplete()){
                    //resp-cond-state = ("OK" / "NO" / "BAD") SP resp-text
                    //return to the prelude...
                    IMAPResponseText text = (IMAPResponseText) res.getObject();
                    condition_state.setResponseText(text);
                    IMAPResponseConditionState copy = condition_state;
                    condition_state = new IMAPResponseConditionState();
                    responseTextParser = new RespTextParser(); //Refresh the parser
                    i = res.getIndex();
                    resp_cond_state = false;
                    line_end = true;
                    prelude = true;
  
                    IMAPResponseData dat = new IMAPResponseData();
                    if(greet){
                        //System.out.println("parse(): Setting the greeting data.");
                        //We just set the response text in the greeting state.
                        greeting.setResponseText(text);
                        dat.setType("greeting");
                        dat.setData(greeting);
                    }else{
                        dat.setType("resp-cond-state");
                        dat.setData(copy);
                    }
                    
                    response.addResponseData(dat);
                    
                }else{
                    i = buffer.length;
                }
            }else if(flag_list){
                ParsingResult res = mailboxParser.parseFlagList(buffer, i);
                if(!res.isSuccess()){
                    //System.out.println("parse(): Parsing failed in flag_list.");
                    return mUtils.parsingFailure(i);
                }
                
                if(res.isComplete()){
                    ArrayList<String> flgs = (ArrayList<String>)res.getObject();
                    data.setFlags(flgs);
                    //Wrap up data
                    IMAPMailboxData copy = data;
                    data = new IMAPMailboxData();
                    IMAPResponseData dat = new IMAPResponseData();
                    dat.setType("mailbox-data");
                    dat.setData(copy);
                    response.addResponseData(dat);
                    i = res.getIndex();
                    flag_list = false;
                    line_end = true;
                    prelude = true;
                }else{
                    i = buffer.length;
                }
                
            }else if(mailbox_list){
                ParsingResult res = mailboxParser.parseMailboxList(buffer, i);
                if(!res.isSuccess()){
                    //System.out.println("parse(): Parsing failed in mailbox_list.");
                    return mUtils.parsingFailure(i);
                }
                
                if(res.isComplete()){
                    IMAPMailboxList lst = (IMAPMailboxList) res.getObject();
                    data.setMailboxList(lst);
                    data.setType("mailbox-list");
                    IMAPMailboxData copy = data;
                    data = new IMAPMailboxData();
                    mailboxParser = new MailboxParser();
                    
                    IMAPResponseData dat = new IMAPResponseData();
                    dat.setType("mailbox-data");
                    dat.setData(copy);
                    response.addResponseData(dat);
                    i = res.getIndex();
                    mailbox_list = false;
                    line_end = true;
                    prelude = true;
                }else{
                    i = buffer.length;
                }
            }else if(nznumbers){
                //SP separated list of nonzero numbers.
                if(b == 32 || b == 13){
                    if(!stack.isEmpty()){
                        //System.out.println("parse(): Empty stack in nznumbers.");
                        //return mUtils.parsingFailure(i);
                    //}
                        byte[] stack_bytes = mUtils.compile(stack);
                        stack.clear();
                        if(!mIMAPParser.validateNZNumber(stack_bytes)){
                            //System.out.println("parse(): NZNumber was not validated.");
                            return mUtils.parsingFailure(i);
                        }
                        int num = Integer.parseInt(new String(stack_bytes, charset));
                        //System.out.println("parse(): Found number " + num);
                        data.addNumber(num);
                    }    
                        if(b == 13){
                            IMAPMailboxData copy = data;
                            data = new IMAPMailboxData();
                            IMAPResponseData dat = new IMAPResponseData();
                            dat.setType("mailbox-data");
                            dat.setData(copy);
                            response.addResponseData(dat);
                            line_end = true;
                            prelude = true;
                            stack.add(b);
                            nznumbers = false;
                            search = false;
                        }
                    
                }else{
                    stack.add(b);
                }
            }else if(status){
                //status-att-list = status-att SP number *(SP status-att SP number)
                if(space){
                    if(b != 32){
                        //System.out.println("parse(): SP token was expected in space state.");
                        return mUtils.parsingFailure(i);
                    }
                    space = false;
                }else if(status_mailbox){
                    ParsingResult res = mailboxParser.parseMailbox(buffer, i);
                    if(!res.isSuccess()){
                        //System.out.println("parse(): Parsing failed in status_mailbox.");
                        return mUtils.parsingFailure(i);
                    }
                    if(res.isComplete()){
                        String mb = (String) res.getObject();
                        data.setMailbox(mb);
                        i = res.getIndex();
                        status_mailbox = false;
                        status_list = true;
                        space = true;
                    }else{
                        i = buffer.length;
                    }
                }else if(status_list){
                    //We alternate between status-att and corresponding number in this state.
                    ParsingResult res = mailboxParser.parseStatusAttList(buffer, i);
                    if(!res.isSuccess()){
                        //System.out.println("parse(): Parsing failed in status_list.");
                        return mUtils.parsingFailure(i);
                    }
                    if(res.isComplete()){
                        HashMap<String, Integer> attributes = (HashMap<String, Integer>) res.getObject();
                        data.setAttributes(attributes);
                        status_list = false;
                        IMAPMailboxData copy = data;
                        data = new IMAPMailboxData();
                        IMAPResponseData dat = new IMAPResponseData();
                        dat.setType("mailbox-data");
                        dat.setData(copy);
                        response.addResponseData(dat);
                        i = res.getIndex();
                        status_list = false;
                        status = false;
                        line_end = true;
                        prelude = true;
                    }
                }
            }else if(number){
                //We determine if we are dealing with mailbox or message data in the number state.
                if(b == 32 || b == 13){
                    if(stack.isEmpty()){
                        //System.out.println("parse(): Empty stack in number.");
                        return mUtils.parsingFailure(i);
                    }
                    byte[] stack_bytes = mUtils.compile(stack);
                    stack.clear();
                    String arg = new String(stack_bytes, charset);
                    //System.out.println("parse(): Handling the arg " + arg + " in number state.");
                    if(arg.equals("EXISTS") || arg.equals("RECENT")){
                        //mailbox-data
                        data.setType(arg);
                        if(arg.equals("EXISTS")){
                            data.setExists(number_stack.pop());
                        }else{
                            data.setRecent(number_stack.pop());
                        }
                        IMAPMailboxData copy = data;
                        data = new IMAPMailboxData();
                        IMAPResponseData dat = new IMAPResponseData();
                        dat.setType("mailbox-data");
                        dat.setData(copy);
                        response.addResponseData(dat);
                        //line_end = true;
                        prelude = true;
                    }else if(arg.equals("EXPUNGE")){
                        //Its done
                        msg.setType("expunge");
                        msg.setMSN(number_stack.pop());
                        IMAPMessageData copy = msg;
                        msg = new IMAPMessageData();
                        IMAPResponseData dat = new IMAPResponseData();
                        dat.setType("message-data");
                        dat.setData(copy);
                        response.addResponseData(dat);
                        //line_end = true;
                        prelude = true;
                    }else if(arg.equals("FETCH")){
                        fetch = true;
                    }
                    
                    if(b == 13){
                        stack.add(b);
                        line_end = true;
                    }
                    
                    number = false;
                    
                }else{
                    stack.add(b);
                }
            }else if(capability){
                //We start the parser at the arguments
                ParsingResult res = dataParser.parseCapabilityDataArgs(buffer, i);
                if(!res.isSuccess()){
                    //System.out.println("parse(): Parsing failed in capability.");
                    return mUtils.parsingFailure(i);
                }
                if(res.isComplete()){
                    ArrayList<String> caps = (ArrayList<String>) res.getObject();
                    IMAPResponseData dat = new IMAPResponseData();
                    i = res.getIndex();
                    dat.setType("capability");
                    dat.setData(caps);
                    response.addResponseData(dat);
                    dataParser = new ResponseDataParser();
                    capability = false;
                    line_end = true;
                    prelude = true;
                }else{
                    i = buffer.length;
                }
            }else if(continue_request){
                ParsingResult res = responseParser.parseContinueReq(buffer, i);
                if(!res.isSuccess()){
                    //System.out.println("parse(): Parsing failed in continue_request.");
                    return mUtils.parsingFailure(i);
                }
                
                if(res.isComplete()){
                    IMAPContinuationRequest req = (IMAPContinuationRequest) res.getObject();
                    response.addContinuationRequest(req);
                    responseParser = new ResponseParser();
                    i = res.getIndex();
                    //continue_request = false; remains true
                    line_end = true;
                    //prelude = true;
                }else{
                    i = buffer.length;
                }
            }else if(fetch){
                ParsingResult res = attributeParser.parseMsgAtt(buffer, i);
                if(!res.isSuccess()){
                    //System.out.println("parse(): Parsing failed in fetch.");
                    return mUtils.parsingFailure(i);
                }
                if(res.isComplete()){
                    ArrayList<IMAPMsgAtt> attributes = (ArrayList<IMAPMsgAtt>)res.getObject();
                    msg.setType("fetch");
                    msg.setMSN(number_stack.pop());
                    msg.setData(attributes);
                    IMAPMessageData copy = msg;
                    msg = new IMAPMessageData();
                    IMAPResponseData dat = new IMAPResponseData();
                    dat.setType("message-data");
                    dat.setData(copy);
                    response.addResponseData(dat);
                    i = res.getIndex();
                    attributeParser = new MsgAttParsing();
                    line_end = true;
                    prelude = true;
                }else{
                    i = buffer.length;
                }
            }
        }
        //System.out.println("parse(): Response not finished. More bytes needed to finish parsing.");
        return new ParsingResult();
    }
    
    
    
    
    
    
    
    public IMAPResponseParser(){
        
    }

    //NOT USED - IGNORE...
    /* compileResponse() is used by the IMAP client to see if the response has been entirely read in. If blocks are read in at a time then a
    ** ByteArrayOutputStream stores them. Once the response-done line is reached complete is set to true.
    **
    ** @param byte[] bytes - The response 
    ** @param String linecode - The current linecode
    */
    public void compileResponse(byte[] bytes, String linecode){
        //RFC 5301 p.88
        //response = *(continue-req / response-data) response-done
        //We parse one line at a time.
        System.out.println("compileResponse(): Method called.");
        for(byte b : bytes){
            if(line_prelude){
                //We read until we hit a space or CRLF
                if(b == 32){
                    System.out.println("compileResponse(): Checking the first atom of the line.");
                    if(!stack.isEmpty()){
                        String atom = new String(mUtils.compile(stack));
                        if(atom.equals(linecode)){
                            System.out.println("compileResponse(): The atom is the linecode. Moving to the response_done_line state.");
                            //This is presumably the response-done line
                            response_done_line = true;
                        }else if(atom.equals("*")){
                            System.out.println("compileResponse(): The atom is a *. Moving to the line_check state to check the next atom.");
                            //We have to check if this is a response-fatal line
                            line_check = true;
                        }else{
                            System.out.println("compileResponse(): Just a standard line.");
                            line = true;
                        }
                        System.out.println("compileResponse(): Exiting the line_prelude state.");
                        line_prelude = false;
                        stack.clear();
                    }else{
                        //Error
                        error = true;
                        return;
                    }
                }else if(b == 13){
                    System.out.println("compileResponse(): Reached a CR character in the line_prelude state.");
                    //Move directly to the line state
                    stack.clear();
                    line_prelude = false;
                    line = true;
                    end_of_line = true;
                }else{
                    stack.add(b);
                }
            }else if(line){
                //We end the line upon reaching CRLF
                if(end_of_line){
                    if(b == 10){
                        System.out.println("compileResponse(): Reached the LF character in the line state. Line complete.");
                        //The line is complete, move to the prelude state
                        end_of_line = false;
                        line = false;
                        line_prelude = true;
                    }else{
                        //Error
                        error = true;
                        return;
                    }
                }else{
                    //We skip the bytes until we reach CR
                    if(b == 13){
                        System.out.println("compileResponse(): Reached the CR character in the line state.");
                        end_of_line = true;
                    }
                }
            }else if(response_done_line){
                //In this state we ensure that the response is complete. We iterate until we hit a space then test for one of the resp-cond-state
                //options.
                if(b == 32){
                    System.out.println("compileResponse(): Reached a space in the response_done_line state.");
                    if(!stack.isEmpty()){
                        String cond = new String(mUtils.compile(stack), charset);
                        //TODO: Store the error!!! 
                        
                        if(cond.equals("OK") || cond.equals("BAD") || cond.equals("NO")){
                            System.out.println("compileResponse(): We have recieved the response-done line. Complete set to true.");
                            //We are done
                            try{
                                out.write(bytes);
                            }catch(IOException e){
                                //indicate an error
                                error = true;
                            }
                            response_done_line = false;
                            complete = true;
                        }else{
                            //Error
                            error = true;
                            return;
                        }
                    }else{
                        //Error
                        error = true;
                        return;
                    }
                }else{
                    stack.add(b);
                }
            }else if(line_check){
                switch (b) {
                    case 32:
                        System.out.println("compileResponse(): Reached a space in the line_check state.");
                        //We stop on the first whitespace and check the atom
                        if(!stack.isEmpty()){
                            String resp = new String(mUtils.compile(stack), charset);
                            if(resp.equals("BYE")){
                                System.out.println("compileResponse(): We have the response-done line. Fatal error returned.");
                                //We have a fatal error
                                error = true;
                                return;
                            }
                            System.out.println("compileResponse(): Exiting the line_check state and moving to the line state.");
                            line_check = false;
                            line = true;
                            stack.clear();
                        } 
                        break;
                    case 13:
                        //We jump into the line state with end of line set
                        line = true;
                        end_of_line = true;
                        line_check = false;
                        break;
                    default:
                        stack.add(b);
                        break;
                }
            }
        }
    }
    
    public boolean isFinished(){
        return complete;
    }
    
    public boolean isError(){
        return error;
    }
    
    public byte[] getBytes(){
        try{
            out.flush();
            return out.toByteArray();
        }catch(IOException e){
            
        }
        return null;
    }
}

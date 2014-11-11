/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.swist.equip;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import javax.xml.bind.DatatypeConverter;

/**
 *
 * @author Mathis
 */
public class DataHelpers {

    public static String getMyIpAddress() {
        String ipAddress = null;
        try {
            InetAddress addr = InetAddress.getLocalHost();
            String hostname = addr.getHostName();
            ipAddress = addr.getHostAddress();
        //    System.out.println(addr.getHostAddress());
         //   System.out.println(hostname);
        } catch (UnknownHostException e) {

        }
        return ipAddress;
    }

    public static Integer singleToInt(byte singleByte) {
        Integer result = 0;
        result = (singleByte & 0xff);
        return result;

    }
    public static byte[] intToByte(int i){
        ByteBuffer b = ByteBuffer.allocate(4);
        b.putInt(i);
        byte[] result = b.array();
       for(byte bytes : result){
           System.out.format("0x%x ", bytes);
       }
        return result;
    }
    public static Integer toInt(byte[] byteArray) {
        Integer result = 0;

        for (int i = 0; i < byteArray.length - 1; i++) {
            result = ((byteArray[i] & 0xff) << 8) | ((byteArray[i + 1] & 0xff));

        }
        return result;

    }

    public static byte[] toByteArray(String s) {
    return DatatypeConverter.parseHexBinary(s);
}
    
    public static String macAdressConvertor(byte[] array){
        String macAdressString;
        macAdressString = Arrays.toString(array);
        return macAdressString;
        
    }
    
    public static String byteArrayToString(byte[] byteArray) {
        StringBuilder newString = new StringBuilder();
        for(byte b :byteArray){
        newString.append(b);
        }
        return newString.toString();
    }
}

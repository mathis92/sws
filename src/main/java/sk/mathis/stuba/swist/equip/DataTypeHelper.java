/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.swist.equip;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import sk.mathis.stuba.swist.analysers.Frame;
import sk.mathis.stuba.swist.analysers.Analyser;

/**
 *
 * @author Mathis
 */
public class DataTypeHelper {

    public static Map<Integer, String> tcpMap;
    public static Map<Integer, String> udpMap;
    public static Map<Integer, String> portMap;
    public static String portFilePath = null;
    public static ArrayList<String> otherPorts = new ArrayList<>();
    static final ClassLoader loader = DataTypeHelper.class.getClassLoader();

    public static Integer singleToInt(byte singleByte) {
        Integer result = 0;
        result = (singleByte & 0xff);
        return result;

    }

    public static Integer toInt(byte[] byteArray) {
        Integer result = 0;

        for (int i = 0; i < byteArray.length - 1; i++) {
            result = ((byteArray[i] & 0xff) << 8) | ((byteArray[i + 1] & 0xff));

        }
        return result;

    }
public static Map sortByValue(Map map) {
     List list = new LinkedList(map.entrySet());
     Collections.sort(list, new Comparator() {
          @Override
          public int compare(Object o1, Object o2) {
               return ((Comparable) ((Map.Entry) (o1)).getValue())
              .compareTo(((Map.Entry) (o2)).getValue());
          }
     });

    Map result = new LinkedHashMap();
    for (Iterator it = list.iterator(); it.hasNext();) {
        Map.Entry entry = (Map.Entry)it.next();
        result.put(entry.getKey(), entry.getValue());
    }
    return result;
} 


    public static String bToString(byte singleByte) {
        StringBuilder newString = new StringBuilder();
        newString.append(String.format("%02X", singleByte));
        return newString.toString();
    }

    public static String macAdressConvertor(byte[] macAdressByteArray) {
        String macAdress = null;
        for (int i = 0; i < 6; i++) {
            if (macAdress != null) {
                macAdress = macAdress + ":" + DataTypeHelper.bToString(macAdressByteArray[i]);
            } else {
                macAdress = DataTypeHelper.bToString(macAdressByteArray[i]);
            }
        }
        return macAdress;

    }

    public static String getUdpPortName(Integer port) {

        String portName = udpMap.get(port);
        if (portName == null) {
            portName = "unknown";
        }

        return portName;
    }

    public static String getTcpPortName(Integer port) {

        String portName = tcpMap.get(port);
        if (portName == null) {
            portName = "unknown";
        }
        return portName;
    }

    public static String ipAdressConvertor(byte[] ipAdressByteArray) {
        String ipAdress = null;
        for (int i = 0; i < 4; i++) {
            if (ipAdress != null) {
                ipAdress = ipAdress + "." + DataTypeHelper.singleToInt(ipAdressByteArray[i]);
            } else {
                ipAdress = DataTypeHelper.singleToInt(ipAdressByteArray[i]).toString();
            }
        }
        return ipAdress;

    }

    public static Integer getIhl(byte rByte) {
        Integer output = 0;
        output = DataTypeHelper.singleToInt(rByte);
        output = output & 0x0F;
        return output;
    }

    
    public static byte[] parseStringMacAddress(String stringMac){
        byte[] macAddress = new byte[6];
        String[] stringMacArray = stringMac.split(":");
        for (int i = 0; i < 6; i++) {
                macAddress[i] = (byte) Integer.parseInt(stringMacArray[i], 16);
            }
        
        return macAddress;
    }
    
    public static byte[] parseStringIpAddress(String stringIp){
        byte[] ipAddress = new byte[4];
        String[] stringIpAddress = stringIp.split(":");
        for (int i = 0; i < 4; i++) {
                ipAddress[i] = (byte) Integer.parseInt(stringIpAddress[i], 16);
            }
        
        return ipAddress;
    }
    
    
    
    public static void scanFile() throws FileNotFoundException, IOException {
        try {
            try {
                BufferedReader reader = null;
                tcpMap = new HashMap<>();
                udpMap = new HashMap<>();

                InputStream is = DataTypeHelper.class.getResourceAsStream("/sk/mathis/stuba/files/ports.txt");
                reader = new BufferedReader(new InputStreamReader(is));
                String line = reader.readLine();
                while (line != null) {
                    if (line != null) {
                        line = line.replaceAll("\t", " ").replaceAll("  ", " ");
                        String[] protocolName = line.split(" ");
                        String[] protocolCode = protocolName[1].split("/");
                        //  System.out.println(protocolName[0] + " -> " + protocolCode[0] + " -> " + protocolCode[1]);
                        if (protocolCode[1].toString().equalsIgnoreCase("udp")) {
                            udpMap.put(Integer.parseInt(protocolCode[0]), protocolName[0]);

                        } else if (protocolCode[1].toString().equalsIgnoreCase("tcp")) {
                            tcpMap.put(Integer.parseInt(protocolCode[0]), protocolName[0]);

                        }
                    }
                    line = reader.readLine();
                }
                reader.close();
                tcpMap = sortByValue(tcpMap);
                udpMap = sortByValue(udpMap);
            } catch (FileNotFoundException ex) {
                Logger.getLogger(Analyser.class.getName()).log(Level.SEVERE, null, ex);
            }
        } catch (IOException ex) {
            Logger.getLogger(Analyser.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    public static void scanProtocolFile() {
        try {
            try {
                BufferedReader reader = null;
                portMap = new HashMap<>();
                InputStream is = DataTypeHelper.class.getResourceAsStream("/sk/mathis/stuba/files/protocols.txt");
                reader = new BufferedReader(new InputStreamReader(is));
                String line = reader.readLine();
                while (line != null) {
                    if (line != null) {
                        line = line.replaceAll(" ", "");
                        String[] protocolName = line.split("/");
                        // System.out.println(protocolName[0] + "->" + protocolName[1]);
                        portMap.put(Integer.parseInt(protocolName[0]), protocolName[1]);
                    }
                    line = reader.readLine();
                }
                reader.close();
            } catch (FileNotFoundException ex) {
                Logger.getLogger(Analyser.class.getName()).log(Level.SEVERE, null, ex);
            }
        } catch (IOException ex) {
            Logger.getLogger(Analyser.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public static String getStringFromArray() {
        String output = null;
        if (otherPorts.isEmpty()) {
            output = " -- ";
        }
        for (String temp : otherPorts) {
            if (output == null) {
                output = temp;
            } else {
                output += ", " + temp;
            }
        }

        return output;
    }

    public static String getIcmpType(Integer type) throws FileNotFoundException {
        String typeMessage = null;
        try {

            FileReader file = new FileReader("\\files\\IcmpTypes.txt");
            Scanner scan = new Scanner(file);
            while (scan.hasNext()) {
                if (scan.hasNextInt()) {
                    if (scan.nextInt() == type) {
                        while (scan.hasNextInt() != true) {
                            if (typeMessage == null) {
                                typeMessage = scan.next();
                            } else {
                                typeMessage += " " + scan.next();
                            }
                        }
                        break;
                    }
                } else {
                    scan.next();
                }
            }
            file.close();
        } catch (IOException e) {
        }

        return typeMessage;
    }
}

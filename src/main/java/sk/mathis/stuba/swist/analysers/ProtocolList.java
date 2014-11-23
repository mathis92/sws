/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.swist.analysers;

import java.util.ArrayList;
import sk.mathis.stuba.swist.equip.ProtocolItem;
/**
 *
 * @author martinhudec
 */
public class ProtocolList {

    private ArrayList<ProtocolItem> protoList = new  ArrayList<>();
    private String port = null;
    
    public ProtocolList(ArrayList<ProtocolItem> protoList, String tcpPort) {
        this.protoList = protoList;
        this.port = tcpPort;
    }

    public ArrayList<ProtocolItem> getProtoList() {
        return protoList;
    }

    public String getPort() {
        return port;
    }
    
    
    
   
}

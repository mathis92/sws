/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.swist.equip;

import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author martinhudec
 */
public class ProtocolItem {

    private Integer layer;
    private String protocol;
    private Integer count = 0;
    private ArrayList<String> tcpPort = new ArrayList<>();
    private ArrayList<Integer> tcpPortCount = new ArrayList<>();
 private ArrayList<String> udpPort = new ArrayList<>();
    private ArrayList<Integer> udpPortCount = new ArrayList<>();
    private Integer otherCount = 0;
    
    
    public ProtocolItem(String protocol, Integer layer) {
        this.protocol = protocol;
        this.layer = layer;
        this.count++;
        
    }

      
    public void countUp() {
        count++;
    }

    public Integer getOtherCount() {
        return otherCount;
    }
    public void incrOther(){
        otherCount++;
    }
    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public void setLayer(Integer layer) {
        this.layer = layer;
    }

    public String getProtocol() {
        return protocol;
    }

    public Integer getCount() {
        return count;
    }

    public Integer getLayer() {
        return layer;
    }

    public ArrayList<String> getTcpPort() {
        return tcpPort;
    }

    public ArrayList<Integer> getTcpPortCount() {
        return tcpPortCount;
    }

    public ArrayList<String> getUdpPort() {
        return udpPort;
    }

    public ArrayList<Integer> getUdpPortCount() {
        return udpPortCount;
    }
    
    
    
    
}

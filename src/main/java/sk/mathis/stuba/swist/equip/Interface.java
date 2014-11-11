/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.swist.equip;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.concurrent.CopyOnWriteArrayList;
import org.jnetpcap.PcapIf;

/**
 *
 * @author Mathis
 */
public class Interface {

  
    
    private PcapIf device;
    private CopyOnWriteArrayList<MacAddress> SrcMacaddressList;
    private Integer state = 1; 

    public Interface(PcapIf device) throws IOException {
        this.device = device;
        SrcMacaddressList = new CopyOnWriteArrayList<>();
    }

    public void addMacAddress(byte[] macadress) {
        SrcMacaddressList.add(new MacAddress(macadress, new Date()));
    }

    public CopyOnWriteArrayList<MacAddress> getSrcMacaddressList() {
        return SrcMacaddressList;
    }

    public Integer getState() {
        return state;
    }

    public void setActive() {
        state = 1;
    }
    public void setDisabled(){
        state = 0;
    }
  
  

    public PcapIf getDevice() {
        return device;
    }

}

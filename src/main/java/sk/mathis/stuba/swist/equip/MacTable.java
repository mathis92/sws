/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package sk.mathis.stuba.swist.equip;

import java.io.IOException;
import java.util.ArrayList;
import java.util.concurrent.CopyOnWriteArrayList;
import org.jnetpcap.PcapIf;


/**
 *
 * @author Mathis
 */
public class MacTable {
    CopyOnWriteArrayList<Interface> interfaceList;
    public MacTable() {
        interfaceList = new CopyOnWriteArrayList<>();
    }
    
    public void addIterface(PcapIf device) throws IOException{
        interfaceList.add(new Interface(device));
    }

    public CopyOnWriteArrayList<Interface> getInterfaceList() {
        return interfaceList;
    }
 
    
}

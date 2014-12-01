/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.swist.equip;

import java.io.IOException;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.concurrent.CopyOnWriteArrayList;
import org.jnetpcap.PcapIf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sk.mathis.stuba.swist.analysers.Analyser;

/**
 *
 * @author Mathis
 */
public class MacTable {

    CopyOnWriteArrayList<Interface> interfaceList;
    private Analyser analyzer;
    private Logger logger = LoggerFactory.getLogger(MacTable.class);
    
    public MacTable() {
        interfaceList = new CopyOnWriteArrayList<>();
        analyzer = new Analyser();
    }

    public void addIterface(PcapIf device) throws IOException {
        interfaceList.add(new Interface(device));
    }

    public CopyOnWriteArrayList<Interface> getInterfaceList() {
        return interfaceList;
    }

    public void flushMacTable(){
        for(Interface interf : interfaceList){
                logger.debug("mac table cleaning port " + interf.getDevice().getName() );
                interf.getSrcMacaddressList().clear();
            }
    }
    
    
    public void CheckCableChange(Packet packet) {
        analyzer.analyzePacket(packet.getPacket());
        Boolean mismatch = false;
        for (Interface interf : interfaceList) {
            for (MacAddress srcMac : interf.getSrcMacaddressList()) {
                logger.debug("packet dstMac " + DataTypeHelper.macAdressConvertor(analyzer.getFrame().getDstMacAddress()) + " switch port mac address " + DataTypeHelper.macAdressConvertor(srcMac.getSrcMacAddress()));
                logger.debug("mac table port " + interf.getDevice().getName() + " packet received on port " + packet.getDevice().getName());
                if (Arrays.equals(analyzer.getFrame().getSrcMacAddress(), srcMac.getSrcMacAddress()) && !interf.getDevice().getName().equals(packet.getDevice().getName())) {
                    System.out.println("switch cable mismatch");
                    mismatch = true;
                    break;
                }
            }
            if(mismatch == true){
                break;
            }
        }
        if(mismatch == true ){
            
            this.flushMacTable();
        }

    }

}

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.swist.sendreceive;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedDeque;
import org.jnetpcap.PcapIf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sk.mathis.stuba.swist.equip.MacTable;
import sk.mathis.stuba.swist.equip.Packet;
import sk.mathis.stuba.swist.equip.ActivityListener;
import sk.mathis.stuba.swist.equip.DataTypeHelper;
import sk.mathis.stuba.swist.equip.Interface;
import sk.mathis.stuba.swist.equip.Statistics;

public class SwitchManager {

    private final Queue<Packet> buffer;
    private final DeviceFinder devFinder;
    private final MacTable macTable;
    private PacketForwarder forwarder;
    private final ArrayList<PacketReceiver> receiverList;
    private final ActivityListener activityListener;
    private Statistics statistic;
    
    public SwitchManager() throws IOException {
        buffer = new ConcurrentLinkedDeque();
        devFinder = new DeviceFinder();
        macTable = new MacTable();
        receiverList = new ArrayList<>();
        activityListener = new ActivityListener(macTable);
        statistic = new Statistics();
        DataTypeHelper.scanFile();
        DataTypeHelper.scanProtocolFile();
        startSwitch();

    }

    public void startSwitch() throws IOException {

        
        for (PcapIf dev : devFinder.getEthDevs()) {
            PacketReceiver receiver = new PacketReceiver(dev, buffer, macTable);
            macTable.addIterface(dev);
            receiver.startThread();
            
            receiverList.add(receiver);

        }
        forwarder = new PacketForwarder(buffer, devFinder.getEthDevs(), receiverList, macTable);
        new Thread(activityListener).start();
        new Thread(forwarder).start();
    }

    public ArrayList<PacketReceiver> getReceiverList() {
        return receiverList;
    }

    public void startReceiverThread(String name) {
        for (PacketReceiver receiver : receiverList) {
            if (receiver.getDevice().getName().equals(name)) {
                receiver.startThread();
            }
        }

    }

    public void interruptReceiverThread(String name) {
        Integer i = 0;
        for (PacketReceiver receiver : receiverList) {
            if (receiver.getDevice().getName().equals(name)) {
                receiver.stop();
                receiver.getPcap().breakloop();
                receiver.getPcap().close();
                receiver.setPcap(null);
                for(Interface interf : receiver.getMacTable().getInterfaceList()){
                    if(interf.getDevice().getName().equals(name)){
                        interf.getSrcMacaddressList().clear();
                    }
                }

            }
            i++;
        }
    }

    public MacTable getMacTable() {
        return macTable;
    }

    public Statistics getStatistic() {
        return statistic;
    }
    
    

}

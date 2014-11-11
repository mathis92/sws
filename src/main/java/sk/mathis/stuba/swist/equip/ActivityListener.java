/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.swist.equip;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author martinhudec
 */
public class ActivityListener implements Runnable {

    MacTable macTable;

    public ActivityListener(MacTable macTable) {
        this.macTable = macTable;
    }

    @Override
    public void run() {

        while (true) {

            for (Interface iface : macTable.getInterfaceList()) {
                for (MacAddress mAddr : iface.getSrcMacaddressList()) {
                    if (mAddr.getLastActiveTime() > 60) {
                        iface.getSrcMacaddressList().remove(mAddr);
                    }
                }
            }

            try {
                Thread.sleep(5000);
            } catch (InterruptedException ex) {
                Logger.getLogger(ActivityListener.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

    }

}

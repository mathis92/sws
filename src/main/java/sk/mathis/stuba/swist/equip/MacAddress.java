/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.swist.equip;

import java.util.Date;

public class MacAddress {
            private byte[] srcMacAddress;
        private Date lastActiveTime;
        public MacAddress(byte[] srcMacAddress, Date lastActiveTime) {
            this.srcMacAddress = srcMacAddress;
            this.lastActiveTime = lastActiveTime;
        }

        public long getLastActiveTime() {
            return (new Date().getTime() - lastActiveTime.getTime())/1000;
        }

        public byte[] getSrcMacAddress() {
            return srcMacAddress;
        }

        public void setLastActiveTime() {
            this.lastActiveTime = new Date();
        }

        public void setSrcMacAddress(byte[] srcMacAddress) {
            this.srcMacAddress = srcMacAddress;
        }
       
}

package isrl.inha.kr;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

import java.util.Random;

public class WS extends Sampler {


    public boolean is_sampled(BasicPacketInfo basicPacketInfo){
        return true;// without sampling process every packet (AKA every packet is sampled)
    }
}

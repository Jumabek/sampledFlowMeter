package isrl.inha.kr;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

public abstract class Sampler {
    private static int seed[] = {123,234,345,456};

    public int getSeed(int index){
        return seed[index];
    }

    public abstract boolean is_sampled(BasicPacketInfo basicPacketInfo);
}


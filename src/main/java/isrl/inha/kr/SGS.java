//Fast Filtered Sampling. Implemented with RPS.
package isrl.inha.kr;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

import java.util.Random;

public class SGS extends Sampler {
    private double error_bound;
    private Random random;
    private int sgs_counter[];
    private int LC_size;
    public SGS(double error_bound, int LC_size){
        this.error_bound = error_bound;
        this.random = new Random(this.getSeed(0));
        this.LC_size = LC_size;
        this.sgs_counter = new int[this.LC_size];
    }

    public boolean is_sampled(BasicPacketInfo basicPacketInfo){
        long hash_value = basicPacketInfo.getIntIPHash();
        int idx = (int) (hash_value%this.LC_size);

        sgs_counter[idx]++;
        double r = (double) random.nextInt(Integer.MAX_VALUE)/Integer.MAX_VALUE;
        if(r<1/(1.0+error_bound*sgs_counter[idx]))
            return true;
        return false;
    }
}

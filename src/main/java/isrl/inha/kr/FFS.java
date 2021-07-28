//Fast Filtered Sampling. Implemented with RPS.
package isrl.inha.kr;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;
import java.util.Random;

public class FFS extends Sampler {
    private int sampling_interval;
    private int est;
    private int counter=0;
    private Random random;
    private int ffs_counter[];
    private int LC_size;
    private int param_s;
    private int param_l;
    private int sampler_counter = 0;
    public FFS(int sampling_interval, int lc_size,int param_s, int param_l){
        this.sampling_interval = sampling_interval;
        this.random = new Random(this.getSeed(0));
        this.est = generateRandomIntWithinRange(1,2*sampling_interval-1);
        this.LC_size = lc_size;
        this.ffs_counter = new int[this.LC_size];
        this.param_s = param_s;
        this.param_l = param_l;
    }

    public int generateRandomIntWithinRange(int min, int max) {
        return random.nextInt((max - min) + 1) + min;
    }

    public boolean is_sampled(BasicPacketInfo basicPacketInfo){
        //String flowid = basicPacketInfo.getFlowId();
        //long hash_value = basicPacketInfo.getHashValue();
        //long hash_value = basicPacketInfo.get3tupleHash();
        long hash_value = basicPacketInfo.getIntIPHash();
        int cntr_index = (int) (hash_value%this.LC_size);

        ffs_counter[cntr_index]++;

        if(ffs_counter[cntr_index]>param_l)
            ffs_counter[cntr_index]=0;
        else if(ffs_counter[cntr_index]<param_s) {
            //pass into SAMPLING module
            //SAMPLING module starts
            sampler_counter++;
            if (sampler_counter == est) {
                sampler_counter = 0;
                est = generateRandomIntWithinRange(1, 2 * sampling_interval - 1);
                return true;
            }
            //end of SAMPLING  module
        }
        return false;
    }
}

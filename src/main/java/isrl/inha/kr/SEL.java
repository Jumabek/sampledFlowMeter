//Fast Filtered Sampling. Implemented with RPS.
package isrl.inha.kr;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

import java.util.Random;

public class SEL extends Sampler {
    private float z, c, n;
    private Random randoms[];
    private int sel_counter[];
    private int LC_size;
    public SEL(float z, float c, float n, int LC_size){
        this.z = z;
        this.c = c;
        this.n = n;
        this.randoms = new Random[2];
        this.randoms[0] = new Random(this.getSeed(0));
        this.randoms[1] = new Random(this.getSeed(1));
        this.LC_size = LC_size;
        this.sel_counter = new int[this.LC_size];
    }

    private boolean is_selected(float z, float c, float n, int  x){
        //small flow
        if(x<z){
            if(this.randoms[0].nextInt()%(int)(1./c)==0) return true;
            else return false;
        }
        //larger flow
        else{
            if(this.randoms[1].nextInt()%(int)(n*x/z)==0) return true;
            else return false;
        }
    }

    public boolean is_sampled(BasicPacketInfo basicPacketInfo){
        //String flowid = basicPacketInfo.getFlowId();
        //long hash_value = basicPacketInfo.getHashValue();
        //long hash_value = basicPacketInfo.get3tupleHash();
        long hash_value = basicPacketInfo.getIntIPHash();
        int cntr_index = (int) (hash_value%this.LC_size);
        int x = ++sel_counter[cntr_index];
        if(is_selected(z,c,n,x)){
            return true;
        }
        else {
            return false;
        }
    }

}

package isrl.inha.kr;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

import java.util.Arrays;
import java.util.Random;


public class SFS extends Sampler{
    private int num_layers;
    private float sampling_interval;
    private Random randoms[];
    private int lc_size_per_level;
    private int non_triggering_bits;
    private int[][] sf;
    public SFS(int total_lc_size, float sampling_interval, int num_layers, int non_triggering_bits){
        this.num_layers = num_layers;
        this.non_triggering_bits = non_triggering_bits;

        this.sampling_interval = sampling_interval;

        this.lc_size_per_level = (total_lc_size)/num_layers;
        this.sf = new int[num_layers][lc_size_per_level];

        this.randoms = new Random[num_layers];
        for(int i = 0; i< num_layers; i++) {
            this.randoms[i] = new Random(this.getSeed(i));
            Arrays.fill(this.sf[i], 0);
        }
    }

    public boolean is_sampled(BasicPacketInfo basicPacketInfo){

        //note, converting long hash value to int was only necessary for sketchflow,
        // doing so for other samplers such as SGS and SEL breaks consistency with c implementations.
        long lhash_value = basicPacketInfo.getIntIPHash();
        int hash_value = (int)(lhash_value%Integer.MAX_VALUE);

        int vector = vector_maker(hash_value);
        int loc = hash_value%lc_size_per_level;
        int randn;
        for(int l = 0; l < num_layers; l++) {
            randn = randoms[l].nextInt(lc_size_per_level);

            sf[l][loc] |= (0x1 << (randn * 4)) << ((hash_value >> (randn * 4)) & 0x3);

            if(pop_count(sf[l][loc] & vector)>non_triggering_bits) {
                sf[l][loc] &= ~vector;

                if(l == num_layers-1)
                    return true;
                    //ans+= sr;//triggered
            }else
                break;
        }
        return false;
    }

    public int vector_maker(int hash_value){
        return (0x1<<(hash_value & 0x3)) | (0x10<<((hash_value>>4) & 0x3))
                | (0x100<<((hash_value>>8) & 0x3)) | (0x1000<<((hash_value>>12) & 0x3))
                | (0x10000<<((hash_value>>16) & 0x3)) | (0x100000<<((hash_value>>20) & 0x3))
                | (0x1000000<<((hash_value>>24) & 0x3)) | (0x10000000<<((hash_value>>28) & 0x3));
    }


    public int pop_count(int value) {
        value = (value & 0x55555555) + ((value >>> 1) & 0x55555555);
        value = (value & 0x33333333) + ((value >>> 2) & 0x33333333);
        value = (value & 0x0F0F0F0F) + ((value >>> 4) & 0x0F0F0F0F);
        value = (value & 0x00FF00FF) + ((value >>> 8) & 0x00FF00FF);
        value = (value & 0x0000FFFF) + ((value >>> 16) & 0x0000FFFF);
        return value;
    }



}

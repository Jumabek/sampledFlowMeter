package cic.cs.unb.ca.jnetpcap.worker;

import cic.cs.unb.ca.jnetpcap.BasicFlow;
import java.util.ArrayList;

public interface HashtableFlushListener {
    void onTableFlushed(ArrayList<BasicFlow> flow_list,  long currentTimestamp);
}

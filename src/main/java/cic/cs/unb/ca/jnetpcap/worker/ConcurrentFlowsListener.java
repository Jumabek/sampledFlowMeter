package cic.cs.unb.ca.jnetpcap.worker;

import cic.cs.unb.ca.jnetpcap.BasicFlow;

import java.util.ArrayList;

public interface ConcurrentFlowsListener {
    void whenSecondPasses(long num_concurrent_flows, long currentTimestamp, long wsafCount);
}

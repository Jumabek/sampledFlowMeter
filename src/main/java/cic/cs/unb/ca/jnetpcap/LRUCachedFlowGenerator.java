package cic.cs.unb.ca.jnetpcap;

import cic.cs.unb.ca.jnetpcap.worker.FlowGenListener;
import cic.cs.unb.ca.jnetpcap.worker.HashtableFlushListener;
import cic.cs.unb.ca.jnetpcap.worker.ConcurrentFlowsListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Set;
import java.util.List;

import static cic.cs.unb.ca.jnetpcap.Utils.LINE_SEP;


public class LRUCachedFlowGenerator {
    public static final Logger logger = LoggerFactory.getLogger(LRUCachedFlowGenerator.class);

	private FlowGenListener mListener;
	private HashtableFlushListener hfListener;
    private ConcurrentFlowsListener cfListener;
	private QueueAssistedLRUCache lruCache;

	private boolean bidirectional;
	private long    flowActivityTimeOut;
	private long    flowActiveTimeout;
	private long    flowIdleTimeout;
	private long    hashtableFlushInterval;
	private long    lruCacheSize;
    private long    num_kickouts;
    private long    num_early_kickout_records;
    private long    numOfFlushes;
    private int mcs_in_second = 1000000;
    private long concurrentFlowsWindow; // 1 second
    private long previousSecondTimestamp = 0;


    public LRUCachedFlowGenerator(boolean bidirectional, long activityTimeout, long flowActiveTimeout,  long flowIdleTimeout, long cacheSize,
                                  long hashtableFlushInterval) {
		super();
		this.bidirectional = bidirectional;
		this.flowActivityTimeOut = activityTimeout;
        this.flowActiveTimeout = flowActiveTimeout;
        this.flowIdleTimeout = flowIdleTimeout;

		this.lruCacheSize = cacheSize;
        this.num_kickouts=0;
		this.num_early_kickout_records = 0;
        this.hashtableFlushInterval = hashtableFlushInterval;
        this.concurrentFlowsWindow = 1000000; // 1 sec
        this.numOfFlushes = 0;

		init();
	}		
	
	private void init(){
		lruCache = new QueueAssistedLRUCache(this.lruCacheSize);
	}

	public void addFlowListener(FlowGenListener listener) {
		mListener = listener;
	}
    public void addFlushListener(HashtableFlushListener listener) {
        hfListener = listener;
    }
    public void addCFListener(ConcurrentFlowsListener listener) {
        cfListener = listener;
    }

    public void addPacket(BasicPacketInfo packet){
        if(packet == null) {
            return;
        }
        
    	BasicFlow   flow;
        BasicFlow returnedFlow=null;
    	long        currentTimestamp = packet.getTimeStamp();


//    	//check for table flush
    	if(currentTimestamp - lruCache.lastFlushTime > hashtableFlushInterval){
            ArrayList<BasicFlow> flushed_records = lruCache.flushTable(currentTimestamp,flowActiveTimeout,flowIdleTimeout);
            this.numOfFlushes++;
            if (hfListener != null) {
                hfListener.onTableFlushed(flushed_records,currentTimestamp);
            }
        }

    	//check if second is passed and count concurrent flows
        if (currentTimestamp - previousSecondTimestamp> mcs_in_second){ // second passed
            long num_concurrent_flows = lruCache.getNumOfConcurrentFlows(currentTimestamp,concurrentFlowsWindow);
            if (cfListener != null) {
                cfListener.whenSecondPasses(num_concurrent_flows,currentTimestamp,lruCache.getNumberOfItems());
            }
            previousSecondTimestamp=currentTimestamp;
        }


        //adding packet
        if(lruCache.containsKey(packet.getFlowId())){
    		flow = lruCache.getEntry(packet.getFlowId());
    		// Flow finished due flowtimeout: 
    		// 1.- we move the flow to finished flow list / AKA dump into CSV file
    		// 2.- we eliminate the flow from the current flow list
    		// 3.- we create a new flow with the packet-in-process
    		if((currentTimestamp -flow.getFlowStartTime())>this.flowActiveTimeout) {
                if (flow.packetCount() > 0) {
                    if (mListener != null) {
                        mListener.onFlowGenerated(flow);
                    }/*elseempty{
                        finishedFlows.put(getFlowCount(), flow);
                    }*/
                    //flow.endActiveIdleTime(currentTimestamp,this.flowActivityTimeOut, this.flowTimeOut, false);
                }
                lruCache.removeEntry(packet.getFlowId());
                returnedFlow = lruCache.putEntry(packet.getFlowId(),
                        new BasicFlow(bidirectional, packet, flow.getSrc(), flow.getDst(), flow.getSrcPort(), flow.getDstPort(),this.flowActivityTimeOut));

            // Flow finished due to IDLE timeout:
            // 1.- we dump the record into CSV file
            // 2.- we eliminate the record from Flow Cache
            // 3.- we create a new entry with the packet-in-process
    		} else if(currentTimestamp-flow.getLastSeen()>this.flowIdleTimeout){
                if (flow.packetCount() > 0) {
                    if (mListener != null) {
                        mListener.onFlowGenerated(flow);
                    }
                }
                lruCache.removeEntry(packet.getFlowId());
                returnedFlow = lruCache.putEntry(packet.getFlowId(),
                        new BasicFlow(bidirectional, packet, flow.getSrc(), flow.getDst(), flow.getSrcPort(), flow.getDstPort(), this.flowActivityTimeOut));

        	// Flow finished due FIN flag (tcp only):
    		// 1.- we add the packet-in-process to the flow (it is the last packet)
        	// 2.- we move the flow to finished flow list
        	// 3.- we eliminate the flow from the current flow list   	
    		}else if(packet.hasFlagFIN()){
    	    	logger.debug("FlagFIN current has {} flow",lruCache.getNumberOfItems());
    	    	flow.addPacket(packet);
                if (mListener != null) {
                    mListener.onFlowGenerated(flow);
                } /*else {
                    finishedFlows.put(getFlowCount(), flow);
                }*/
                lruCache.removeEntry(packet.getFlowId());
    		}else{
    			flow.updateActiveIdleTime(currentTimestamp,this.flowActivityTimeOut);
    			flow.addPacket(packet);
                returnedFlow = lruCache.putEntry(packet.getFlowId(), flow);
    		}
    	}else{
            returnedFlow = lruCache.putEntry(packet.getFlowId(), new BasicFlow(bidirectional,packet));
    	}

    	//exporting kicked out flow
        if(returnedFlow !=null) {
            if (returnedFlow.packetCount() > 0) {
                if (mListener != null) {
                    logger.debug("Kicked flow with packetCOunt() == ",returnedFlow.packetCount(),"is dumped");
                    mListener.onFlowGenerated(returnedFlow);
                    this.num_kickouts++;
                }
                else{
                        System.out.println("mListener is null");
                        System.exit(1);
                    }
                //flow.endActiveIdleTime(currentTimestamp,this.flowActivityTimeOut, this.flowTimeOut, false);
            }

            //count early kickout
            if(currentTimestamp - returnedFlow.getFlowStartTime() < flowActiveTimeout || currentTimestamp - returnedFlow.getLastSeen() < flowIdleTimeout){// then, it is early kickout
                this.num_early_kickout_records+=1;
                //System.out.println(String.format("Number of early kick-outs so far %d",this.num_early_kickout_records));
            }

        }

    }

    public long  writeNumberOfEarlyKickedRecords(String fileFullPath) {
        if (fileFullPath == null ) {
            String ex = String.format("fullFilePath=%s,filename=%s", fileFullPath);
            throw new IllegalArgumentException(ex);
        }

        File file = new File(fileFullPath);
        FileOutputStream output = null;
        long early_kicked_count = this.num_early_kickout_records;
        try {
            output = new FileOutputStream(file, false);
            output.write(String.valueOf(early_kicked_count).getBytes());
        } catch (IOException e) {
            logger.debug(e.getMessage());
        } finally {
            try {
                if (output != null) {
                    output.flush();
                    output.close();
                }
            } catch (IOException e) {
                logger.debug(e.getMessage());
            }
        }
        return early_kicked_count;
    }
    public long  writeNumberKickedRecords(String fileFullPath) {
        if (fileFullPath == null ) {
            String ex = String.format("fullFilePath=%s,filename=%s", fileFullPath);
            throw new IllegalArgumentException(ex);
        }

        File file = new File(fileFullPath);
        FileOutputStream output = null;
        long count = this.num_kickouts;
        try {
            output = new FileOutputStream(file, false);
            output.write(String.valueOf(count).getBytes());
        } catch (IOException e) {
            logger.debug(e.getMessage());
        } finally {
            try {
                if (output != null) {
                    output.flush();
                    output.close();
                }
            } catch (IOException e) {
                logger.debug(e.getMessage());
            }
        }
        return count;
    }

    public int dumpLabeledFlowBasedFeatures(String path, String filename,String header){
    	BasicFlow   flow;
    	int         total = 0;
    	int   zeroPkt = 0;

    	try {
    		//total = finishedFlows.size()+currentFlows.size(); becasue there are 0 packet BasicFlow in the currentFlows

    		FileOutputStream output = new FileOutputStream(new File(path+filename));
			logger.debug("dumpLabeledFlow: ", path + filename);
    		/*output.write((header+"\n").getBytes());
    		Set<Integer> fkeys = finishedFlows.keySet();    		
			for(Integer key:fkeys){
	    		flow = finishedFlows.get(key);
                if (flow.packetCount() > 1) {
                    output.write((flow.dumpFlowBasedFeaturesEx() + "\n").getBytes());
                    total++;
                } else {
                    zeroPkt++;
                }
            }*/
            //logger.debug("dump Labeled finished records -> {},{}",zeroPkt,total);

            Set<String> ckeys = lruCache.getKeySet();
			for(String key:ckeys){
	    		flow = lruCache.getEntry(key);
	    		if(flow.packetCount()>0) {
                    output.write((flow.dumpFlowBasedFeaturesEx() + "\n").getBytes());
                    total++;
                }else{
                    zeroPkt++;
                }

			}
            logger.debug("dump Labeled finished+current records -> {},{}",zeroPkt,total);
            output.flush();
            output.close();
        } catch (IOException e) {

            logger.debug(e.getMessage());
        }

        return total;
    }       

    public long dumpLabeledCurrentFlow(String fileFullPath,String header) {
        if (fileFullPath == null || header==null) {
            String ex = String.format("fullFilePath=%s,filename=%s", fileFullPath);
            throw new IllegalArgumentException(ex);
        }

        File file = new File(fileFullPath);
        FileOutputStream output = null;
        int total = 0;
        try {
            if (file.exists()) {
                output = new FileOutputStream(file, true);
            }else{
                if (file.createNewFile()) {
                    output = new FileOutputStream(file);
                    output.write((header + LINE_SEP).getBytes());
                }
            }

            Set<String> ckeys = lruCache.getKeySet();
            BasicFlow flow;
            for(String key:ckeys){
                flow = lruCache.getEntry(key);
                if(flow.packetCount()>0) {
                    output.write((flow.dumpFlowBasedFeaturesEx() + LINE_SEP).getBytes());
                    total++;
                }else{

                }
            }

        } catch (IOException e) {
            logger.debug(e.getMessage());
        } finally {
            try {
                if (output != null) {
                    output.flush();
                    output.close();
                }
            } catch (IOException e) {
                logger.debug(e.getMessage());
            }
        }
        return total;
	}

    public long dumpSampledPktCount(String fileFullPath, int spc) {
        if (fileFullPath == null ) {
            String ex = String.format("fullFilePath=%s,filename=%s", fileFullPath);
            throw new IllegalArgumentException(ex);
        }

        File file = new File(fileFullPath);
        FileOutputStream output = null;
        int total = 0;
        try {
            output = new FileOutputStream(file, false);
            output.write(String.valueOf(spc).getBytes());
        } catch (IOException e) {
            logger.debug(e.getMessage());
        } finally {
            try {
                if (output != null) {
                    output.flush();
                    output.close();
                }
            } catch (IOException e) {
                logger.debug(e.getMessage());
            }
        }
        return total;
    }
}

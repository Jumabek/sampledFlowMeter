package cic.cs.unb.ca.ifm;

import cic.cs.unb.ca.flow.FlowMgr;
import cic.cs.unb.ca.jnetpcap.*;
import cic.cs.unb.ca.jnetpcap.worker.ConcurrentFlowsListener;
import cic.cs.unb.ca.jnetpcap.worker.FlowGenListener;
import cic.cs.unb.ca.jnetpcap.worker.HashtableFlushListener;
import cic.cs.unb.ca.jnetpcap.worker.InsertCsvRow;
import isrl.inha.kr.*;
import org.apache.commons.io.FilenameUtils;
import org.apache.logging.log4j.core.util.Integers;
import org.jnetpcap.PcapClosedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import swing.common.SwingUtils;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.*;

import static cic.cs.unb.ca.Sys.FILE_SEP;

public class SampleMeterMemLimited {

    public static final Logger logger = LoggerFactory.getLogger(SampleMeterMemLimited.class);
    private static final String DividingLine = "-------------------------------------------------------------------------------";
    private static String[] animationChars = new String[]{"|", "/", "-", "\\"};
    private static Sampler sampler;
    private static int cache_size;
    private static long activityTimeout =          5000000L;   // 5 sec

    private static long activeFlowTimeout =            120000000L;   // 2 min (default)
    private static long idleFlowTimeout =               15000000L;   // for No Sampling case (default)
    private static long flushInterval =            1000000;   // 1 sec

    private static int MCS_IN_SEC = 1000000;
    private static double mean_IAT = 222158; // in MCs (0.2 sec) obtained for CIC-IDS-2018, cannot verify in which setting this was extracted.
    // for idle timeout of 15 sec on without sampling case, IAT is 0.222223

    public static void main(String[] args) {
        String rootPath = System.getProperty("user.dir");
        String pcapPath;
        String outPath;
        String sampling_technique;
        double sampling_rate;

        if (args.length < 1) {
            logger.info("Please select pcap!");
            return;
        }
        pcapPath = args[0];
        File in = new File(pcapPath);

        if(in==null || !in.exists()){
            logger.info("The pcap file or folder does not exist! -> {}",pcapPath);
            return;
        }

        if (args.length < 2) {
            logger.info("Please select output folder!");
            return;
        }
        outPath = args[1];
        File out = new File(outPath);
        if (out == null || out.isFile()) {
            logger.info("The out folder does not exist! -> {}",outPath);
            return;
        }

        sampling_rate = Float.parseFloat(args[2]);
        activeFlowTimeout += (100./sampling_rate-1)*mean_IAT;
        idleFlowTimeout += (100./sampling_rate-1)*mean_IAT; // due to sampling there is additional time between two sampled packets, depends on SR

        System.out.println(String.format("Flow Cache Settings: (%d,%d)\n",activeFlowTimeout, idleFlowTimeout));
        if (args.length < 4) {
            logger.info("Please select a Sampling Technique: (choices: SRS - Random Packet Sampling, SGS - Sketch Guided Sampling, " +
                    "FFS - Fast Filtered Sampling, SFS - SketchFlow Sampling, WS - Without Sampling)");
            return;
        }

        sampling_technique = args[3]; //SRS, FFS, SFS, SGS, WS

        if (args.length<5){
            logger.info("Please specify cache size (#entries)");
        }

        cache_size = Integers.parseInt(args[4]);

        if (sampling_technique.equals("SRS")) {
            if(args.length<6)
            {
                logger.info("Specify sampling interval for SRS");
                return;
            }
            int sampling_interval = Integers.parseInt(args[5]);
            sampler = new RPS(sampling_interval);
        }
        else if(sampling_technique.equals("FFS")){
            if(args.length<9)
            {
                logger.info("Please specify 1) sampling interval 2) LC size 3) s-small flow size and \n 4) l- large flow size for FFS sampler");
                return;
            }
            int sampling_interval = Integers.parseInt(args[5]);
            int lc_size = Integers.parseInt(args[6]);
            int param_s = Integers.parseInt(args[7]);
            int param_l = Integers.parseInt(args[8]);

            sampler = new FFS(sampling_interval, lc_size, param_s, param_l);
        }
        else if(sampling_technique.equals("SFS")){
            if(args.length<9)
            {
                logger.info("Please specify 4) sampling interval 5) nflows 6) num_layers for SketchFlow Sampler\n" +
                        "7) number of non triggering bits");
                return;
            }
            float sampling_interval = Float.parseFloat(args[5]);
            int lc_size = Integers.parseInt(args[6]);
            int num_layers = Integers.parseInt(args[7]);
            int non_triggering_bits = Integers.parseInt(args[8]);
            sampler = new SFS(lc_size,sampling_interval,num_layers, non_triggering_bits);
        }
        else if (sampling_technique.equals("SGS")) {
            if(args.length<7)
            {
                logger.info("Specify 4) Error Bound and 5) LC_size for SGS");
                return;
            }
            double error_bound = Double.parseDouble(args[5]);
            int LC_size = Integers.parseInt(args[6]);
            sampler = new SGS(error_bound,LC_size);
        }
        else if (sampling_technique.equals("SEL")) {
            if(args.length<9)
            {
                logger.info("Specify 4) z,  5) c, 6) n and 7) LC_size for SEL");
                return;
            }
            float z = Float.parseFloat(args[5]);
            float c = Float.parseFloat(args[6]);
            float n = Float.parseFloat(args[7]);
            int LC_size = Integers.parseInt(args[8]);
            sampler = new SEL(z,c,n,LC_size);
        }
        else if (sampling_technique.equals("WS")) {
            int flush_interval_in_seconds = Integers.parseInt(args[5]);
            flushInterval = flush_interval_in_seconds * MCS_IN_SEC;//modify flush interval programmatically
            sampler = new WS();
        }

        else{
            System.out.println(String.format("No implementation for sampler %s",sampling_technique));
            return;
        }

        logger.info("You select: {}",pcapPath);
        logger.info("Out folder: {}",outPath);
        logger.info("Sampling Technique: {}",sampling_technique);


        if (in.isDirectory()) {
            readPcapDir(in,outPath,activityTimeout, activeFlowTimeout, idleFlowTimeout);
        } else {
            if (!SwingUtils.isPcapFile(in)) {
                logger.info("Please select pcap file!");
            } else {
                logger.info("CICFlowMeter received 1 pcap file");
                readPcapFile(in.getPath(), outPath,activityTimeout, activeFlowTimeout, idleFlowTimeout);
            }
        }
    }


    private static void readPcapDir(File inputPath, String outPath, long activityTimeout, long flowActiveTimeout, long flowIdleTimeout) {
        if(inputPath==null||outPath==null) {
            return;
        }
        File[] pcapFiles = inputPath.listFiles(SwingUtils::isPcapFile);
        int file_cnt = pcapFiles.length;
        System.out.println(String.format("CICFlowMeter found :%d pcap files", file_cnt));

        for(int i=0;i<file_cnt;i++) {
            File file = pcapFiles[i];
            if (file.isDirectory()) {
                continue;
            }
            int cur = i + 1;
            System.out.println(String.format("==> %d / %d", cur, file_cnt));
            readPcapFile(file.getPath(),outPath,activityTimeout, flowActiveTimeout, flowIdleTimeout);

        }
        System.out.println("Completed!");
    }

    private static void readPcapFile(String inputFile, String outPath, long activityTimeout, long flowActiveTimeout, long flowIdleTimeout) {
        if(inputFile==null ||outPath==null ) {
            System.out.println(String.format("%s or %s is null",inputFile,outPath));
            return;
        }
        String filename = FilenameUtils.getName(inputFile);

        if(!outPath.endsWith(FILE_SEP)){
            outPath += FILE_SEP;
        }

        File saveFileFullPath = new File(outPath+filename+FlowMgr.FLOW_SUFFIX);
        File saveFileSPCFullPath = new File(outPath+filename+FlowMgr.SAMPLED_PKT_COUNT_SUFFIX);

        File saveFileEarlyKickoutFullPath = new File(outPath+filename+FlowMgr.EARLY_KICKOUT_COUNT);
        File saveFileKickoutFullPath = new File(outPath+filename+FlowMgr.KICKOUT_COUNT);



        if (saveFileFullPath.exists()) {
           if (!saveFileFullPath.delete()) {
               System.out.println("Save file can not be deleted");
           }
        }

        String filenameForCF = String.format("MemoryUsage_FI_%d",flushInterval/MCS_IN_SEC );//;
        File saveConcurrencyCountFullPath = new File(outPath+filenameForCF+FlowMgr.FLOW_SUFFIX);
        if (saveConcurrencyCountFullPath.exists()) {
            if (!saveConcurrencyCountFullPath.delete()) {
                System.out.println("saveConcurrencyCountFullPath file can not be deleted");
            }
        }

        LRUCachedFlowGenerator flowGen = new LRUCachedFlowGenerator(true, activityTimeout, flowActiveTimeout, flowIdleTimeout,cache_size,
                flushInterval);

        flowGen.addFlowListener(new FlowListener(filename,outPath));
        flowGen.addFlushListener(new FlushListener(filename,outPath));
        flowGen.addCFListener(new CFListener(filenameForCF,outPath));

        boolean readIP6 = false;
        boolean readIP4 = true;
        
        PacketReader packetReader = new PacketReader(inputFile, readIP4, readIP6);

        System.out.println(String.format("Working on... %s",filename));

        int nValid=0;
        int nTotal=0;
        int sampledTotal=0;
        int nDiscarded = 0;
        long start = System.currentTimeMillis();
        int i=0;

        System.out.println(String.format("Entering a loop"));
        while(true) {
            /*i = (i)%animationChars.length;
            System.out.print("Working on "+ inputFile+" "+ animationChars[i] +"\r");*/
            try{
                BasicPacketInfo basicPacket = packetReader.nextPacket();
                nTotal++;
                    if(basicPacket !=null && (basicPacket.getProtocol()==6 ||basicPacket.getProtocol()==17)){
                        if (sampler.is_sampled(basicPacket)) {
                            sampledTotal++;
                            flowGen.addPacket(basicPacket);

                        }
                        nValid++;
                    }else{
                        nDiscarded++;
                    }
            }catch(PcapClosedException e){
                break;
            }
            i++;
        }

        System.out.println(String.format("Sampled packet percentage %.2f",100.*sampledTotal/nTotal));

        flowGen.dumpLabeledCurrentFlow(saveFileFullPath.getPath(), FlowFeature.getHeader());
        flowGen.dumpSampledPktCount(saveFileSPCFullPath.getPath(),sampledTotal);
        flowGen.writeNumberOfEarlyKickedRecords(saveFileEarlyKickoutFullPath.getPath());
        flowGen.writeNumberKickedRecords(saveFileKickoutFullPath.getPath());

        long lines = SwingUtils.countLines(saveFileFullPath.getPath());

        System.out.println(String.format("%s is done. total %d flows ",filename,lines));

    }

    static class FlowListener implements FlowGenListener {

        private String fileName;
        private String outPath;

        private long cnt;

        public FlowListener(String fileName, String outPath) {
            this.fileName = fileName;
            this.outPath = outPath;
        }

        @Override
        public void onFlowGenerated(BasicFlow flow) {

            String flowDump = flow.dumpFlowBasedFeaturesEx();
            List<String> flowStringList = new ArrayList<>();
            flowStringList.add(flowDump);
            InsertCsvRow.insert(FlowFeature.getHeader(),flowStringList,outPath,fileName+ FlowMgr.FLOW_SUFFIX);

            cnt++;
            String console = String.format("%s -> %d flows \r", fileName,cnt);
            System.out.print(console);
        }
    }

    static class FlushListener implements HashtableFlushListener {

        private String fileName;
        private String outPath;

        private long cnt;

        public FlushListener(String fileName,  String outPath) {
            this.fileName = fileName;
            this.outPath = outPath;
            this.cnt=0;
        }

        @Override
        public void onTableFlushed(ArrayList<BasicFlow> flow_list, long currentTimestamp) {
            //dump completed flows
            if (flow_list.size()>0) {
                List<String> flowStringList = new ArrayList<>();
                for (int i = 0; i < flow_list.size(); i++) {
                    BasicFlow flow = flow_list.get(i);
                    String flowDump = flow.dumpFlowBasedFeaturesEx();
                    flowStringList.add(flowDump);
                    cnt++;
                }
                InsertCsvRow.insert(FlowFeature.getHeader(), flowStringList, outPath, fileName + FlowMgr.FLOW_SUFFIX);
                String console = String.format("%s -> %d records \r", fileName, cnt);
                System.out.print(console);
            }
        }

    }

    static class CFListener implements ConcurrentFlowsListener {

        private String fileName;
        private String outPath;

        public CFListener(String fileName,String outPath) {
            this.fileName = fileName;
            this.outPath = outPath;
        }

        @Override
        public void whenSecondPasses(long num_concurrent_flows, long currentTimestamp, long wsafCount) {

                String header = "Timestamp,#concurrentFlows,#WSAF";
                List<String> flowStringList = new ArrayList<>();
                flowStringList.add(String.format("%d,%d,%d",currentTimestamp,num_concurrent_flows,wsafCount));
                InsertCsvRow.insert(header, flowStringList, outPath, fileName + FlowMgr.FLOW_SUFFIX);

                String console = String.format("#concurrent flows: %d | #WSAF:%d\r", num_concurrent_flows,wsafCount);
                System.out.print(console);
        }


    }
}


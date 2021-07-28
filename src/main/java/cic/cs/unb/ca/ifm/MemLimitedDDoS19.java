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
import java.util.*;
import java.util.ArrayList;
import java.util.List;

import static cic.cs.unb.ca.Sys.FILE_SEP;

class SortbyPcapOrder implements Comparator<String>
{
    // Used for sorting in ascending order of
    // roll number
    public int compare(String a, String b)
    {
        int index = a.lastIndexOf("_");
        int a_number = Integer.parseInt(a.substring(index+1));

        index = b.lastIndexOf("_");
        int b_number = Integer.parseInt(b.substring(index+1));


        return a_number - b_number;
    }
}

public class MemLimitedDDoS19 {

    public static final Logger logger = LoggerFactory.getLogger(MemLimitedDDoS19.class);
    private static final String DividingLine = "-------------------------------------------------------------------------------";
    private static String[] animationChars = new String[]{"|", "/", "-", "\\"};
    private static Sampler sampler;
    private static int cache_size;
    private static long flowTimeout =            120000000L;   // 2 min
    private static long activityTimeout =          5000000L;   // 5 sec
    private static long idleTimeout =          50000000L;   // 50 sec

    private static long flushInterval =          1000000;   // 1 sec
    public static void main(String[] args) {


        String rootPath = System.getProperty("user.dir");
        String pcapPath;
        String outPath;
        String sampling_technique;


        /* Select path for reading all .pcap files */
        /*if(args.length<1 || args[0]==null) {
            pcapPath = rootPath+"/data/in/";
        }else {
        }*/

        /* Select path for writing all .csv files */
        /*if(args.length<2 || args[1]==null) {
            outPath = rootPath+"/data/out/";
        }else {
        }*/

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

        if (args.length < 3) {
            logger.info("Please select a Sampling Technique: (choices: RPS - Random Packet Sampling, SGS - Sketch Guided Sampling, " +
                    "FFS - Fast Filtered Sampling, SEL - Selective Flow Sampling, SKS - SketchFlow Sampling, WS - Without Sampling)");
            return;
        }
        sampling_technique = args[2]; //RPS, FFS, SKS, SGS, SEL, WS

        if (args.length<4){
            logger.info("Please specify memory size");
        }
        cache_size = Integers.parseInt(args[3]);
        if (sampling_technique.equals("RPS")) {
            if(args.length<5)
            {
                logger.info("Specify sampling interval for RPS");
                return;
            }
            int sampling_interval = Integers.parseInt(args[4]);
            sampler = new RPS(sampling_interval);
        }
        else if(sampling_technique.equals("FFS")){
            if(args.length<8)
            {
                logger.info("Please specify 1) sampling interval 2) LC size 3) s-small flow size and \n 4) l- large flow size for FFS sampler");
                return;
            }
            int sampling_interval = Integers.parseInt(args[4]);
            int lc_size = Integers.parseInt(args[5]);
            int param_s = Integers.parseInt(args[6]);
            int param_l = Integers.parseInt(args[7]);

            sampler = new FFS(sampling_interval, lc_size, param_s, param_l);
        }
        else if(sampling_technique.equals("SFS")){
            if(args.length<8)
            {
                logger.info("Please specify 4) sampling interval 5) nflows 6) num_layers for SketchFlow Sampler\n" +
                        "7) number of non triggering bits");
                return;
            }
            float sampling_interval = Float.parseFloat(args[4]);
            int lc_size = Integers.parseInt(args[5]);
            int num_layers = Integers.parseInt(args[6]);
            int non_triggering_bits = Integers.parseInt(args[7]);
            sampler = new SFS(lc_size,sampling_interval,num_layers, non_triggering_bits);
        }
        else if (sampling_technique.equals("SGS")) {
            if(args.length<6)
            {
                logger.info("Specify 4) Error Bound and 5) LC_size for SGS");
                return;
            }
            double error_bound = Double.parseDouble(args[4]);
            int LC_size = Integers.parseInt(args[5]);
            sampler = new SGS(error_bound,LC_size);
        }
        else if (sampling_technique.equals("SEL")) {
            if(args.length<8)
            {
                logger.info("Specify 4) z,  5) c, 6) n and 7) LC_size for SEL");
                return;
            }
            float z = Float.parseFloat(args[4]);
            float c = Float.parseFloat(args[5]);
            float n = Float.parseFloat(args[6]);
            int LC_size = Integers.parseInt(args[7]);
            sampler = new SEL(z,c,n,LC_size);
        }
        else if (sampling_technique.equals("WS")) {
            int MCS_IN_SEC = 1000000;
            int flush_interval_in_seconds = Integers.parseInt(args[4]);
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
            readPcapDir(in,outPath,flowTimeout,activityTimeout);
        } else {
            if (!SwingUtils.isPcapFile(in)) {
                logger.info("Please select pcap file!");
            } else {
                logger.info("CICFlowMeter received 1 pcap file");
                readPcapFile(in.getPath(), outPath,flowTimeout,activityTimeout);
            }
        }
    }


    private static void readPcapDir(File inputPath, String outPath, long flowTimeout, long activityTimeout) {
        if(inputPath==null||outPath==null) {
            return;
        }
        File[] pcapFiles = inputPath.listFiles(SwingUtils::isPcapFile);
        int file_cnt = pcapFiles.length;
        System.out.println(String.format("CICFlowMeter found :%d pcap files", file_cnt));

        List<String> pcapFilenames = new ArrayList<String>();
        for(int i=0;i<file_cnt;i++) {
            File file = pcapFiles[i];
            if (file.isDirectory()) {
                continue;
            }
            pcapFilenames.add(file.getPath());
        }
        System.out.println(String.format("read %d filenames",pcapFilenames.size()));

        Collections.sort(pcapFilenames,new SortbyPcapOrder()); //neceassry for orderly processing of pcap traces

        readPcapFiles(pcapFilenames,outPath, flowTimeout,activityTimeout);

        System.out.println("Completed!");
    }

    private static void readPcapFile(String inputFile, String outPath, long flowTimeout, long activityTimeout) {
        if(inputFile==null ||outPath==null ) {
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

        long hashtableFlushInterval = 120000000L; // 120sec
        String filenameForCF = String.format("MemoryUsage_FI_%d",hashtableFlushInterval/1000000);//;
        File saveConcurrencyCountFullPath = new File(outPath+filenameForCF+FlowMgr.FLOW_SUFFIX);
        if (saveConcurrencyCountFullPath.exists()) {
            if (!saveConcurrencyCountFullPath.delete()) {
                System.out.println("saveConcurrencyCountFullPath file can not be deleted");
            }
        }

        LRUCachedFlowGenerator flowGen = new LRUCachedFlowGenerator(true, flowTimeout, activityTimeout,idleTimeout ,
                cache_size, hashtableFlushInterval);

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

    private static void readPcapFiles(List<String> inputFiles, String outPath, long flowTimeout, long activityTimeout) {
        System.out.println("Calling readPcapFiles");
        if(inputFiles.size()<=0 ||outPath==null ) {
            return;
        }
        String filename="Records";

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

        String filenameForCF = String.format("MemoryUsage_FI_%d",flushInterval/1000000);//;
        File saveConcurrencyCountFullPath = new File(outPath+filenameForCF+FlowMgr.FLOW_SUFFIX);
        if (saveConcurrencyCountFullPath.exists()) {
            if (!saveConcurrencyCountFullPath.delete()) {
                System.out.println("saveConcurrencyCountFullPath file can not be deleted");
            }
        }

        LRUCachedFlowGenerator flowGen = new LRUCachedFlowGenerator(true, flowTimeout, activityTimeout, idleTimeout,
                cache_size, flushInterval);

        flowGen.addFlowListener(new FlowListener(filename,outPath));
        flowGen.addFlushListener(new FlushListener(filename,outPath));
        flowGen.addCFListener(new CFListener(filenameForCF,outPath));

        boolean readIP6 = false;
        boolean readIP4 = true;

        int sampledTotal = 0;
        int j;
        int nTotal = 0, nValid=0, nDiscarded=0;

        int file_cnt = inputFiles.size();
        //processing pcap files one by one
        for(j=0;j<inputFiles.size();j++) {
            String inputFile = inputFiles.get(j);
            int cur = j + 1;
            System.out.println("-----------------------------------------");
            System.out.println(String.format("==> %d / %d", cur, file_cnt));
            System.out.println(String.format("%s",inputFile));

            PacketReader packetReader = new PacketReader(inputFile, readIP4, readIP6);

            System.out.println(String.format("Working on... %s", filename));

            boolean first_packet_in_pcap = true;
            while (true) {
            /*i = (i)%animationChars.length;
            System.out.print("Working on "+ inputFile+" "+ animationChars[i] +"\r");*/
                try {
                    BasicPacketInfo basicPacket = packetReader.nextPacket();
                    nTotal++;

                    if (basicPacket != null && (basicPacket.getProtocol() == 6 || basicPacket.getProtocol() == 17)) {
                        if (sampler.is_sampled(basicPacket)) {
                            sampledTotal++;
                            flowGen.addPacket(basicPacket);
                        }

                        if (first_packet_in_pcap){
                            String time = DateFormatter.parseDateFromLong(basicPacket.getTimeStamp()/1000L, "dd/MM/yyyy hh:mm:ss");
                            System.out.println(String.format("First Packet arrived in %s ",time));
                            first_packet_in_pcap=false;
                        }

                        nValid++;
                    } else {
                        nDiscarded++;
                    }
                } catch (PcapClosedException e) {
                    break;
                }
            }
        }

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
                String console = String.format("%s -> %d flows \r", fileName, cnt);
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


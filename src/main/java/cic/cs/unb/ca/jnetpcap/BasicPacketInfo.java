package cic.cs.unb.ca.jnetpcap;

import java.util.Arrays;

import org.apache.commons.math3.linear.DefaultIterativeLinearSolverEvent;
import org.apache.logging.log4j.core.util.Integers;
import org.jnetpcap.packet.format.FormatUtils;
import java.lang.Math;

public class BasicPacketInfo {

	/*  Basic Info to generate flows from packets  	*/
	private long id;
	private byte[] src;
	private byte[] dst;
	private int srcInt;
	private int dstInt;
	private int srcPort;
	private int dstPort;
	private int protocol;
	private long timeStamp;
	private long payloadBytes;
	private String flowId = null;
	/* ******************************************** */
	private boolean flagFIN = false;
	private boolean flagPSH = false;
	private boolean flagURG = false;
	private boolean flagECE = false;
	private boolean flagSYN = false;
	private boolean flagACK = false;
	private boolean flagCWR = false;
	private boolean flagRST = false;
	private int TCPWindow = -1;
	private long headerBytes;
	private int payloadPacket = 0;

	public BasicPacketInfo(byte[] src, byte[] dst, int srcPort, int dstPort,
						   int protocol, long timeStamp, IdGenerator generator) {
		super();
		this.id = generator.nextId();
		this.src = src;
		this.dst = dst;
		this.srcPort = srcPort;
		this.dstPort = dstPort;
		this.protocol = protocol;
		this.timeStamp = timeStamp;
		generateFlowId();
	}

	public BasicPacketInfo(IdGenerator generator) {
		super();
		this.id = generator.nextId();
	}


	long powerN(long number, int power){
		long res = 1;
		long sq = number;
		while(power > 0){
			if(power % 2 == 1){
				res *= sq;
			}
			sq = sq * sq;
			power /= 2;
		}
		return res;
	}

	public long getHashValue() {
		boolean forward = this.getFlowDirection();
		// source https://stackoverflow.com/questions/9249983/hashcode-giving-negative-values
		long hash = 17;
		if(forward)
		{
			hash = hash * 31 + this.src.hashCode();
			hash = hash * 31 + this.dst.hashCode();
			hash = hash * 31 + srcPort; // I'm assuming this is an int...
			hash = hash * 31 + dstPort; // ditto
			hash = hash * 31 + protocol;
		}
		else
		{
			hash = hash * 31 + this.dst.hashCode();
			hash = hash * 31 + this.src.hashCode();
			hash = hash * 31 + dstPort; // I'm assuming this is an int...
			hash = hash * 31 + srcPort; // ditto
			hash = hash * 31 + protocol;
		}
		if (hash<0){
			System.out.println(String.format("Negative hash value %d",hash));
			System.exit(1);
		}
		return hash;
	}

	public long convertToDecimal(byte[] address){
		long integerAdress = 0;

		boolean forward = this.getFlowDirection();

		if (address.length==4){
			for (int i = 0; i<4; i++){
				int t = address[i] & 0xFF;
				//int t=address[i];
				//if(t<0 && i!=3)
				//	t+=1;
				//System.out.print(String.format("%d.",t));
				integerAdress += t*powerN(256,4-(i+1));
			}
			if (forward) {
				assert this.srcInt == integerAdress : String.format("Adress calculation incorrect for %s where %d vs %d", FormatUtils.ip(address), this.srcInt, integerAdress);
				System.out.println(String.format("Adress calculation for %s where %d vs %d", FormatUtils.ip(address), this.srcInt, integerAdress));
			}
			else {
				assert this.dstInt == integerAdress : String.format("Adress calculation incorrect for %s where %d vs %d", FormatUtils.ip(address), this.dstInt, integerAdress);
				System.out.println(String.format("Adress calculation incorrect for %s where %d vs %d", FormatUtils.ip(address), this.dstInt, integerAdress));
			}
			//System.out.println();
			//System.out.println(integerAdress);
			//System.out.println();
			System.exit(1);
		}

		return integerAdress;
	}

	public long ipAsNumeric(String ipAsString) {
		String[] segments = ipAsString.split("\\.");
		return (long) (Long.parseLong(segments[3]) * 16777216L
				+ Long.parseLong(segments[2]) * 65536L
				+ Long.parseLong(segments[1]) * 256L +
				Long.parseLong(segments[0]));
	}

	public long getIntIPHash(){
		boolean forward = this.getFlowDirection();
		// source https://stackoverflow.com/questions/9249983/hashcode-giving-negative-values
		long hash = 17;
		long sourceIP = ipAsNumeric(this.getSourceIP());
		long destIP = ipAsNumeric(this.getDestinationIP());
		if(forward)
		{

			hash = hash * 31 + sourceIP;//this.srcInt+ Integer.MAX_VALUE;
			hash = hash * 31 + destIP;//this.dstInt+ Integer.MAX_VALUE;
			hash = hash * 31 + srcPort; // I'm assuming this is an int...
			hash = hash * 31 + dstPort; // ditto
			hash = hash * 31 + protocol;
		}
		else
		{
			hash = hash * 31 + destIP;//this.dstInt+ Integer.MAX_VALUE;
			hash = hash * 31 + sourceIP;//this.srcInt+ Integer.MAX_VALUE;
			hash = hash * 31 + dstPort; // I'm assuming this is an int...
			hash = hash * 31 + srcPort; // ditto
			hash = hash * 31 + protocol;
		}
		if (hash<0){
			System.out.println(String.format("Negative hash value %d",hash));
		}
		return hash;
	}

	public long get3tupleHash(){
		boolean forward = this.getFlowDirection();
		long hash = 17;
		if(forward)
		{
			hash = hash * 31 + srcPort; // I'm assuming this is an int...
			hash = hash * 31 + dstPort; // ditto
			hash = hash * 31 + protocol;
		}
		else
		{
			hash = hash * 31 + dstPort; // I'm assuming this is an int...
			hash = hash * 31 + srcPort; // ditto
			hash = hash * 31 + protocol;
		}
		if (hash<0){
			System.out.println(String.format("Negative hash value %d",hash));
		}
		return hash;
	}

	//public long getHashValueStrIP() does not make sense
//		boolean forward = this.getFlowDirection();
//		// source https://stackoverflow.com/questions/9249983/hashcode-giving-negative-values
//		long hash = 17;
//		if(forward)
//		{
//			hash = hash * 31 + this.getSourceIP().hashCode();
//			hash = hash * 31 + this.getDestinationIP().hashCode();
//			hash = hash * 31 + srcPort; // I'm assuming this is an int...
//			hash = hash * 31 + dstPort; // ditto
//			hash = hash * 31 + protocol;
//		}
//		else
//		{
//			hash = hash * 31 + this.getDestinationIP().hashCode();
//			hash = hash * 31 + this.getSourceIP().hashCode();
//			hash = hash * 31 + dstPort; // I'm assuming this is an int...
//			hash = hash * 31 + srcPort; // ditto
//			hash = hash * 31 + protocol;
//		}
//		if (hash<0){
//			System.out.println(String.format("Negative hash value %d",hash));
//		}
//		return hash;
//	}

	public long getCStyleHash(String flowid_str){
		//String flowid_str = getCStyleFlowId();
		System.out.println(flowid_str);
		long hash = 17;
		//System.out.println(String.format("flowid_str = %s",flowid_str));
		for(int i=0; i<flowid_str.length();i++){
			hash = 31*hash + flowid_str.charAt(i);
			//System.out.println(String.format("flowid_str[%d]=%c | +1=%d",i,flowid_str.charAt(i),flowid_str.charAt(i)+1));
		}
		//System.exit(0);
		return hash;
	}

	public int getHashValueShifted() {
		return this.getFlowId().hashCode() & 0x7FFFFFFF;
	}


    public boolean getFlowDirection(){
		boolean forward;
		//Juma wrote following block to idendify the direction
		if (this.srcPort>this.dstPort){ // credit to Jiyoo for informing that client port is always bigger than server port
			forward=true;
		}
		else{
			forward = false;
		}
		// end of Juma's code
		return forward;
	}

	public String generateFlowId(){
    	boolean forward ;
    	
//    	for(int i=0; i<this.src.length;i++){
//    		if(((Byte)(this.src[i])).intValue() != ((Byte)(this.dst[i])).intValue()){
//    			if(((Byte)(this.src[i])).intValue() >((Byte)(this.dst[i])).intValue()){
//    				forward = false;
//    			}
//    			i=this.src.length;
//    		}
//    	}

		//I believe above original code to define direction of flow is incorrect
		//we isntead use our costum defined functino
		forward = getFlowDirection();

        if(forward){
            this.flowId = this.getSourceIP() + "-" + this.getDestinationIP() + "-" + this.srcPort  + "-" + this.dstPort  + "-" + this.protocol;
        }else{
            this.flowId = this.getDestinationIP() + "-" + this.getSourceIP() + "-" + this.dstPort  + "-" + this.srcPort  + "-" + this.protocol;
        }
        return this.flowId;
    }

//    public String getCStyleFlowId(){
//		boolean forward = getFlowDirection();
//		String flowid;
//		if(forward){
//			flowId = convertToDecimal(this.src) + "-" + convertToDecimal(this.dst) + "-" + this.srcPort  + "-" + this.dstPort  + "-" + this.protocol;
//		}else{
//			flowId = convertToDecimal(this.dst) + "-" + convertToDecimal(this.src)+ "-" + this.dstPort  + "-" + this.srcPort  + "-" + this.protocol;
//		}
//		return flowId;
//
//	}


	public String dumpInfo() {
		return null;
	}
	public int getPayloadPacket() {
		return payloadPacket+=1;
	}
          
    
    public String getSourceIP(){
    	return FormatUtils.ip(this.src);
    }

    public String getDestinationIP(){
    	return FormatUtils.ip(this.dst);
    }
    
    
	public long getId() {
		return id;
	}

	public void setId(long id) {
		this.id = id;
	}

	public byte[] getSrc() {
		return Arrays.copyOf(src,src.length);
	}

	public void setSrc(byte[] src) {
		this.src = src;
	}
	public void setIntSource(int srcInt){
		this.srcInt = srcInt;
	}
	public void setIntDestination(int dstInt){
		this.dstInt = dstInt;
	}

	public byte[] getDst() {
		return Arrays.copyOf(dst,dst.length);
	}

	public void setDst(byte[] dst) {
		this.dst = dst;
	}

	public int getSrcPort() {
		return srcPort;
	}

	public void setSrcPort(int srcPort) {
		this.srcPort = srcPort;
	}

	public int getDstPort() {
		return dstPort;
	}

	public void setDstPort(int dstPort) {
		this.dstPort = dstPort;
	}

	public int getProtocol() {
		return protocol;
	}

	public void setProtocol(int protocol) {
		this.protocol = protocol;
	}

	public long getTimeStamp() {
		return timeStamp;
	}

	public void setTimeStamp(long timeStamp) {
		this.timeStamp = timeStamp;
	}

	public String getFlowId() {
		return this.flowId!=null?this.flowId:generateFlowId();
	}


	public void setFlowId(String flowId) {		
		this.flowId = flowId;
	}

	public boolean isForwardPacket(byte[] sourceIP) {
		return Arrays.equals(sourceIP, this.src);
	}

	public long getPayloadBytes() {
		return payloadBytes;
	}

	public void setPayloadBytes(long payloadBytes) {
		this.payloadBytes = payloadBytes;
	}

	public long getHeaderBytes() {
		return headerBytes;
	}

	public void setHeaderBytes(long headerBytes) {
		this.headerBytes = headerBytes;
	}

	public boolean hasFlagFIN() {
		return flagFIN;
	}

	public void setFlagFIN(boolean flagFIN) {
		this.flagFIN = flagFIN;
	}

	public boolean hasFlagPSH() {
		return flagPSH;
	}

	public void setFlagPSH(boolean flagPSH) {
		this.flagPSH = flagPSH;
	}

	public boolean hasFlagURG() {
		return flagURG;
	}

	public void setFlagURG(boolean flagURG) {
		this.flagURG = flagURG;
	}

	public boolean hasFlagECE() {
		return flagECE;
	}

	public void setFlagECE(boolean flagECE) {
		this.flagECE = flagECE;
	}

	public boolean hasFlagSYN() {
		return flagSYN;
	}

	public void setFlagSYN(boolean flagSYN) {
		this.flagSYN = flagSYN;
	}

	public boolean hasFlagACK() {
		return flagACK;
	}

	public void setFlagACK(boolean flagACK) {
		this.flagACK = flagACK;
	}

	public boolean hasFlagCWR() {
		return flagCWR;
	}

	public void setFlagCWR(boolean flagCWR) {
		this.flagCWR = flagCWR;
	}

	public boolean hasFlagRST() {
		return flagRST;
	}

	public void setFlagRST(boolean flagRST) {
		this.flagRST = flagRST;
	}

	public int getTCPWindow(){
		return TCPWindow;
	}

	public void setTCPWindow(int TCPWindow){
		this.TCPWindow = TCPWindow;
	}
}

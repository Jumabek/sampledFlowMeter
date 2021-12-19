# SAMPLEMETER
You may use this code for your research to investigate the impact sampling rate, sampling method, flow cache settings has on Flow Monitoring tools (middleboxes) such as Network Intrusion Detection, Internet Usage Billing, Traffic Engineering Applications.   
It is build on top of [CICFlowMeter](https://github.com/ahlashkari/CICFlowMeter) and allows you to: 

1) extract bi-flow features from sampled packets for different packet sampling rates, 
2) provides option to specify memory used by sampler (E: 1 Mb) 
3) easy way to set Flow Cache memory within python script  


Currently four samplers are supported 
1) SRS - Simple Random Sampling - widely deployed on CISCO routers [[2]](#2)
2) SGS - Sketch Guided Sampling - found to be comparatively better for Network Intrusion Detection (NIDS) from other samplers [[1]](#1). 
3) FFS - Fast Filtered Sampling - also found to be good fit for NIDS [[1]](#1).
4) SFS - SketchFlow Sampling - found to be memory efficient from other sketch based samplers [[3]](#3)


## Data Pre-processing
### CIC-IDS 2018 dataset
Dataset contains many small pcap traces recorded on each PC for a given day.
For simplicity and for the sake of constrained flow cache experiment we merge those pcaps. Specifically pcaps that belong to the same day merged into single pcap file as follows: 

1) fix currupt pcaps with `corrupt_pcapfixer.py` (pcap folder path should be set) 
This process is necessary for pcap_merger.
Note, it takes around 1-2 hours for fixing pcap files of one day

Manual action:
after script finishes, pcap traces that were indeed corrupt will be fixed and stored in the parent folder. You should replace corrupt ones with new fixed pcaps manually.


2) merge pcaps with `pcap_merger.py` (pcap folder path should be set) 


## Flow Feature Exraction
### without Sampling
1) go to `scripts/ids-18` folder 
2) adjust your pcap data path on `WS.py `
3) run `python WS.py`

### with Sampling
Similarly to without sampling case, 
1) go to `scripts/ids-18` folder
2) adjust paths on corressponding file such as `SRS.py, SGS.py, FFS.py, SFS.py`
3) run

## References
<a id="1">[1]</a> 
Jazi, Hossein Hadian, et al. "Detecting HTTP-based application layer DoS attacks on web servers in the presence of sampling." Computer Networks 121 (2017): 25-36.

<a id="2">[2]</a>
Using NetFlow Sampling to Select the Network
Traffic to Track. URL: https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/netflow/configuration/xe-16-6/nf-xe-16-6-book/nflow-filt-samp-traff-xe.pdf

<a id="3">[3]</a>
Jang, Rhongho, et al. "Sketchflow: Per-flow systematic sampling using sketch saturation event." IEEE INFOCOM 2020-IEEE Conference on Computer Communications. IEEE, 2020.









# CICFLOWMETER
## Install jnetpcap local repo

for linux:
1) install libpcap-dev dependancy:
  a) `sudo apt-get update -y`
  b) `sudo apt-get install -y libpcap-dev`
2) sudo is a prerequisite
```
//linux :at the pathtoproject/jnetpcap/linux/jnetpcap-1.4.r1425
//windows: at the pathtoproject/jnetpcap/win/jnetpcap-1.4.r1425
mvn install:install-file -Dfile=jnetpcap.jar -DgroupId=org.jnetpcap -DartifactId=jnetpcap -Dversion=1.4.1 -Dpackaging=jar
```

## Run
### IntelliJ IDEA
open a Terminal in the IDE
```
//linux:
$ sudo bash
$ gradle execute

//windows:
$ gradlew execute
```
### Eclipse

Run eclipse with sudo
```
1. Right click App.java -> Run As -> Run Configurations -> Arguments -> VM arguments:
-Djava.library.path="pathtoproject/jnetpcap/linux/jnetpcap-1.4.r1425"  -> Run

2. Right click App.java -> Run As -> Java Application

```

## Make package

### IntelliJ IDEA
open a Terminal in the IDE
```
//linux:
$ gradle distZip
//window
$ gradlew distZip
```
the zip file will be in the pathtoproject/CICFlowMeter/build/distributions

### Eclipse
At the project root
```
mvn package
```
the jar file will be in the pathtoproject/CICFlowMeter/target

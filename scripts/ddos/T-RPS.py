import os
import time
from utils import ensure_dir 
from utils import get_ddos_train_baseline_mem
from labeler import label_ddos_train

#pcap_dataroot = '/media/juma/data/net_intrusion/ddos19/PCAPs/PCAP-03-11'
pcap_dataroot = '/data/juma/data/ddos/PCAPs/PCAP-01-12'

sampling_interval = 10
sampling_rate = int(100./sampling_interval)
sampler_dir = 'SR_{}'.format(sampling_rate)

executable_dir= '../../build/install/SampleMeter/bin'
os.chdir(executable_dir)

def execute(cmd):
    print(cmd)
    os.system(cmd)

for i in range(1):
    ratio = 1/10.**i
    print("Ratio ", ratio)
    LRU_cache_size = int(ratio*get_ddos_train_baseline_mem())
    csv_dataroot = pcap_dataroot.replace('PCAPs','CSVs_r_{}/{}/RPS_SI_{}'.format(ratio,sampler_dir,sampling_interval))
    ensure_dir(csv_dataroot)

    #sampling
    cmd = './MemLimitedDDoS19CMD "{}" "{}" RPS {} {}'.format(pcap_dataroot,csv_dataroot,LRU_cache_size, sampling_interval)
    execute(cmd)

    #labeling
    print("Labeling")
    label_ddos_train(csv_dataroot)

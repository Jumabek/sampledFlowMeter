import os
from labeler import label_ddos_test
import time
import ntpath
from utils import ensure_dir, get_max_num_concurrent_flows_test
from utils import get_ddos_test_baseline_mem
from os.path import join

def execute(cmd):
    os.system(cmd)

pcap_dataroot = '/media/juma/data/net_intrusion/ddos19/PCAPs/PCAP-03-11'
#pcap_dataroot = '/data/juma/data/ddos/PCAPs/PCAP-03-11'

s=8
l=16
sampling_interval =4
sampler_dir = 'SR_10'
executable_dir = '../../build/install/SampleMeter/bin'
os.chdir(executable_dir)

for i in range(6):
    ratio = 1/10**i
    print("ratio ",ratio)
    csv_dataroot = pcap_dataroot.replace('PCAPs','CSVs_r_{}/{}/FFS_({},{},{})'.format(ratio, sampler_dir,s,l,sampling_interval))
    ensure_dir(csv_dataroot)

    #sampling
    LC_size = get_max_num_concurrent_flows_test()//4 # that is biggest memory fo SFS
    LRU_cache_size = int(ratio*get_ddos_test_baseline_mem())

    cmd = './SampleMeterMemLimitedCMD "{}" "{}" FFS {} {} {} {} {}'.format(pcap_dataroot,csv_dataroot,LRU_cache_size, sampling_interval,LC_size, s, l)
    
    tick = time.time()
    execute(cmd)
    tock = time.time()

    ensure_dir(csv_dataroot+'_l')
    with open(join(csv_dataroot+'_l','sampling_time.txt'),'w') as f:
        f.write('{:.0f}'.format(tock-tick))

    #labeling
    print("Labeling")
    #label_ddos_test(csv_dataroot)



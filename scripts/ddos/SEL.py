import os
from labeler import label_ddos_test
import time
import ntpath
from utils import ensure_dir, get_max_num_concurrent_flows_test
from utils import get_ddos_test_baseline_mem
from os.path import join

def execute(cmd):
    os.system(cmd)

z = 230
c = 1
n = 1 # z/(n*x)
sampler_dir = 'SR_10'

#pcap_dataroot = '/media/juma/data/research/intrusion_detection/dataset/CIC-IDS-2018/PCAPs'
pcap_dataroot = '/data/juma/data/ddos/PCAPs/PCAP-03-11'

executable_dir = '../../build/install/SampleMeter/bin'
os.chdir(executable_dir)


for i in range(0,1):
    ratio = 1./10**i
    print("ratio ",ratio)
    csv_dataroot = pcap_dataroot.replace('PCAPs','CSVs_r_{}/{}/SEL_({},{},{})'.format(ratio,sampler_dir,z,c,n))
    ensure_dir(csv_dataroot)

    #sampling
    LC_size = get_max_num_concurrent_flows_test()//4 # that is biggest memory fo SFS
    #LRU_cache_size = int(ratio*get_ddos_test_baseline_mem())
    LRU_cache_size = 2
    cmd = './MemLimitedDDoS19CMD "{}" "{}" SEL {} {} {} {} {}'.format(pcap_dataroot,csv_dataroot,LRU_cache_size,z,c,n,LC_size)
    
    tick = time.time()
    #execute(cmd)
    tock = time.time()

    ensure_dir(csv_dataroot+'_l')
    #with open(join(csv_dataroot+'_l','sampling_time.txt'),'w') as f:
    #    f.write('{:.0f}'.format(tock-tick))

    #labeling
    label_ddos_test(csv_dataroot)

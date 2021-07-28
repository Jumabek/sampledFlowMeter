import os
from labeler import label_ddos_test
import time
import ntpath
from utils import ensure_dir, get_max_num_concurrent_flows_test
from utils import get_ddos_test_baseline_mem
from os.path import join


#pcap_dataroot = '/media/juma/data/research/intrusion_detection/dataset/CIC-IDS-2018/PCAPs'
pcap_dataroot = '/data/juma/data/ddos/PCAPs/PCAP-03-11'

error_bound = .0028
sampler_dir = 'SR_10'
executable_dir = '../../build/install/SampleMeter/bin'
os.chdir(executable_dir)


def execute(cmd):
    os.system(cmd)

for i in range(6):
    ratio = 1./10**i
    print('ratio ',ratio)
    csv_dataroot = pcap_dataroot.replace('PCAPs','CSVs_r_{}/{}/SGS_e_{}'.format(ratio,sampler_dir,error_bound))
    #sampling
    LC_size = get_max_num_concurrent_flows_test()//4 # that is biggest memory fo SFS
    LRU_cache_size = int(ratio*get_ddos_test_baseline_mem())
    cmd = './SampleMeterMemLimitedCMD "{}" "{}" SGS {} {} {}'.format(pcap_dataroot,csv_dataroot,LRU_cache_size,error_bound,LC_size)
    
    tick = time.time()
    execute(cmd)
    tock = time.time()

    ensure_dir(csv_dataroot+'_l')
    with open(join(csv_dataroot+'_l','sampling_time.txt'),'w') as f:
        f.write('{:.0f}'.format(tock-tick))

    #labeling
    #label_ddos_test(csv_dataroot)


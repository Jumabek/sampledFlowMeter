import os
from labeler import label_ddos_train
import time
import ntpath
from utils import ensure_dir, get_max_num_concurrent_flows_train
from utils import get_ddos_train_baseline_mem

#pcap_dataroot = '/media/juma/data/research/intrusion_detection/dataset/CIC-IDS-2018/PCAPs'
pcap_dataroot = '/data/juma/data/ddos/PCAPs/PCAP-01-12'

error_bound = .0017
sampler_dir = 'SR_10'
executable_dir = '../../build/install/SampleMeter/bin'
os.chdir(executable_dir)


def execute(cmd):
    os.system(cmd)

tick = time.time()
for i in range(1):
    ratio = 1./10**i
    print('ratio ',ratio)
    csv_dataroot = pcap_dataroot.replace('PCAPs','CSVs_r_{}/{}/SGS_e_{}'.format(ratio,sampler_dir,error_bound))
    #sampling
    LC_size = get_max_num_concurrent_flows_train()//4 # that is biggest memory fo SFS
    LRU_cache_size = int(ratio*get_ddos_train_baseline_mem())
    cmd = './SampleMeterMemLimitedCMD "{}" "{}" SGS {} {} {}'.format(pcap_dataroot,csv_dataroot,LRU_cache_size,error_bound,LC_size)
    #execute(cmd)

    #labeling
    label_ddos_train(csv_dataroot)


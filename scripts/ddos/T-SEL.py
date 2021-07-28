import os
from labeler import label_ddos_train
import time
import ntpath
from utils import ensure_dir, get_max_num_concurrent_flows_train
from utils import get_ddos_train_baseline_mem

def execute(cmd):
    os.system(cmd)

pcap_dataroot = '/data/juma/data/ddos/PCAPs/PCAP-01-12'

z = 380
c = 1
n = 1 # z/(n*x)
sampler_dir = 'SR_10'

executable_dir = '../../build/install/SampleMeter/bin'
os.chdir(executable_dir)


for i in range(1):
    ratio = 1./10**i
    print("ratio ",ratio)
    csv_dataroot = pcap_dataroot.replace('PCAPs','CSVs_r_{}/{}/SEL_({},{},{})'.format(ratio,sampler_dir,z,c,n))
    ensure_dir(csv_dataroot)

    #sampling
    LC_size = get_max_num_concurrent_flows_train()//4 # that is biggest memory fo SFS
    LRU_cache_size = int(ratio*get_ddos_train_baseline_mem())
    cmd = './SampleMeterMemLimitedCMD "{}" "{}" SEL {} {} {} {} {}'.format(pcap_dataroot,csv_dataroot,LRU_cache_size,z,c,n,LC_size)
    #execute(cmd)

    #labeling
    label_ddos_train(csv_dataroot)

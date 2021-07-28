import os
from os.path import join
from labeler import label_ddos_test
import time
from utils import ensure_dir
import platform

pcap_dataroot = '/data/juma/data/ddos/PCAPs/PCAP-03-11'

executable_dir= '../../build/install/SampleMeter/bin'

flow_record_size_b = 100*4 # 100 features with float type (4 byte)
memory_m = 1000
converted_memory_kb = 1024*memory_m
converted_memory_b = converted_memory_kb*1024
LRU_cache_size = converted_memory_b//flow_record_size_b # how many flow record can we store in mem

csv_dataroot = pcap_dataroot.replace('PCAPs','CSVs/WS')
ensure_dir(csv_dataroot)

def execute(cmd):
    print(cmd)
    os.system(cmd)

flush_interval_in_sec = 1
cmd = './SampleMeterMemLimitedCMD "{}" "{}" WS {} {}'.format(pcap_dataroot,csv_dataroot,LRU_cache_size,flush_interval_in_sec)

os.chdir(executable_dir)

tick = time.time()
execute(cmd)
tock = time.time()
delta = int(tock-tick)

#write for future reference
#with open(join(csv_dataroot,'sampling_time_{}.txt'.format(platform.release())),'w') as f:
#    f.write('{}'.format(delta))

#labeling
label_ddos_test(csv_dataroot)

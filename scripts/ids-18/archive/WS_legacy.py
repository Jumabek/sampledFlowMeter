import os
import glob
from os.path import join
from labeler import label_ids_2018,move_out
import time
import ntpath
from utils import ensure_dir, get_immediate_subdirs
import platform


def get_hashtable_size(memory_in_m):
    flow_record_size_b = 100*4 # 100 features with float type (4 byte)
    memory_in_m = 10000
    converted_memory_kb = 1024*memory_in_m
    converted_memory_b = converted_memory_kb*1024
    hashtable_size = converted_memory_b//flow_record_size_b # how many flow record can we store in mem
    return hashtable_size

#pcap_dataroot = '/media/juma/data/net_intrusion/CIC-IDS-2018/PCAPs'
pcap_dataroot = '/data/juma/data/ids18/PCAPs'
csv_dataroot = pcap_dataroot.replace('PCAPs','CSVs/WS')
ensure_dir(csv_dataroot)

subdirs = get_immediate_subdirs(pcap_dataroot)

executable_dir= '../../build/install/SampleMeter/bin'
os.chdir(executable_dir)
def execute(cmd):
    print('\n-------------------')
    print(cmd)
    os.system(cmd)

cmds = []
counter=0
flush_interval_in_sec = 1
LRU_cache_size =  get_hashtable_size(memory_in_m=1000)
for d in subdirs:
    if 'Friday-23-02' not in d:
        continue
    for pcap_filename in os.listdir(join(pcap_dataroot,d)):
        pcap_file = join(pcap_dataroot,d,pcap_filename)
        pcap_dir = ntpath.split(pcap_file)[0]
        output_dir = pcap_dir.replace('PCAPs','CSVs/WS')
        ensure_dir(output_dir)

        cmd = './SampleMeterMemLimitedCMD "{}" "{}" WS {} {}'.format(pcap_file,output_dir,LRU_cache_size,flush_interval_in_sec)
        cmds.append(cmd)
        counter+=1

tick = time.time()
for cmd in cmds:
   execute(cmd)
tock = time.time()
print("TOTAL Time it took for sampling: {:0.f}  ",(tock-tick)/60.) # took 80min on desktop

#move_out(csv_dataroot)
#labeling
tick = time.time()
#label_ids_2018(csv_dataroot) # 
tock = time.time()
print("Time take for labeling {:.0f} min".format((tock-tick)/60.))

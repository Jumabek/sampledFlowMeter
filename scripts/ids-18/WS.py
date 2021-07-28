import os
from glob import glob
from os.path import join
from labeler import label_ids_2018, move_out, move_pkt_cnt
from utils import write_labeldist
import time
from utils import ensure_dir, write_flowdist
from multiprocessing import Pool

def get_hashtable_size(memory_in_m):
    flow_record_size_b = 100*4 # 100 features with float type (4 byte)
    memory_in_m = 10000
    converted_memory_kb = 1024*memory_in_m
    converted_memory_b = converted_memory_kb*1024
    hashtable_size = converted_memory_b//flow_record_size_b # how many flow record can we store in mem
    return hashtable_size

pcap_dataroot = '/data/juma/data/ids18/PCAPs'
#pcap_dataroot = '/media/juma/data/net_intrusion/ids18/PCAPs/'
csv_dataroot = pcap_dataroot.replace('PCAPs','CSVs/WS')
ensure_dir(csv_dataroot)


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
for pcap_file in glob(join(pcap_dataroot,'*.pcap')):
    print(pcap_file)
    if 1==1:
        #pcap_dir = ntpath.split(pcap_file)[0]
        pcap_dir = pcap_file.replace('.pcap','')
        output_dir = pcap_dir.replace('PCAPs','CSVs/WS')
        ensure_dir(output_dir)

        cmd = './SampleMeterMemLimitedCMD "{}" "{}" 100 WS {} {}'.format(pcap_file,output_dir,LRU_cache_size,flush_interval_in_sec)
        cmds.append(cmd)
        counter+=1


if 'sample'=='sample':
    tick = time.time()
    p = Pool(9)
    p.map(execute,cmds)
    tock = time.time()
    print("Sampling took : {:0.f} minutes ",(tock-tick)/60.) # took 80min on desktop

if 'label'=='label':
    move_out(csv_dataroot)

    #labeling
    tick = time.time()
    label_ids_2018(csv_dataroot) # 
    tock = time.time()
    print("Time take for labeling {:.0f} min".format((tock-tick)/60.))

    write_labeldist(csv_dataroot+'_l')
    write_flowdist(csv_dataroot+'_l')


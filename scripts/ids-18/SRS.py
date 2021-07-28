import os
from os.path import join
import argparse
import ntpath
import time
from glob import glob
from multiprocessing import Process

from labeler import label_ids_2018, move_out, move_pkt_cnt
from utils import ensure_dir
from utils import get_max_cf, get_max_wsaf
from utils import write_labeldist, write_flow_obsr


#pcap_dataroot = '/mnt/disk3/net_intrusion/ids18/PCAPs'
#pcap_dataroot = '/home/juma/data/net_intrusion/CIC-IDS-2018/PCAPs'
pcap_dataroot = '/data/juma/data/ids18/PCAPs'

parser = argparse.ArgumentParser()
parser.add_argument("--ratio", help="ratio of the memory we use for hashtable, max is 100% WSAF",
                    type=float, default=.001)
args = parser.parse_args()
ratio = args.ratio


sampling_interval = 1000 
sampling_rate = 100./sampling_interval
sampler_dir = 'SR_{:.1f}'.format(sampling_rate)

csv_dataroot = pcap_dataroot.replace('PCAPs','CSVs_r_{}_m_1.0/{}/SRS_SI_{}'.format(ratio,sampler_dir,sampling_interval))


executable_dir= '../../build/install/SampleMeter/bin'
os.chdir(executable_dir)
def execute(cmd):
    print('\n------------------')
    os.system(cmd)
    
cmds = []
for pcap_file in glob(join(pcap_dataroot,'*.pcap')):      
        pcap_dir = pcap_file.replace('.pcap','')
        output_dir = pcap_dir.replace(pcap_dataroot,csv_dataroot)
        ensure_dir(output_dir)
        
        baseline_mem = get_max_wsaf(ntpath.basename(pcap_dir))
        LRU_cache_size = round(baseline_mem*ratio)

        cmd = './SampleMeterMemLimitedCMD "{}" "{}" {} {} {} {}'.format(pcap_file,output_dir,sampling_rate, "SRS", LRU_cache_size, sampling_interval)
        cmds.append(cmd)

if "sample"=='sample':
    tick = time.time()
    procs = [ Process(target=execute, args=[cmd]) for cmd in cmds]
    for p in procs: p.start()
    for p in procs: p.join()

    tock = time.time()
    sampling_time = int(tock-tick)
    print("TOTAL Time it took for sampling: {} sec ",sampling_time)
    with open(join(csv_dataroot,'sampling_time.txt'),'w') as f:
        f.write(str(sampling_time))

if 'label'=='label':
    move_out(csv_dataroot)
    #labeling
    tick = time.time()
    label_ids_2018(csv_dataroot)
    tock = time.time()
    print("Time take for labeling {} sec".format(tock-tick))
    move_pkt_cnt(csv_dataroot)
    write_labeldist(csv_dataroot+'_l')
    write_flow_obsr(csv_dataroot+'_l')


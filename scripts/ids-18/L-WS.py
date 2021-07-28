import os
from glob import glob
from os.path import join
from labeler import label_ids_2018, move_out, move_pkt_cnt
from utils import write_labeldist
import time
from utils import ensure_dir, write_flowdist
from multiprocessing import Pool
import argparse
from utils import get_max_wsaf
import ntpath

pcap_dataroot = '/data/juma/data/ids18/PCAPs'
#pcap_dataroot = '/media/juma/data/net_intrusion/ids18/PCAPs/'
parser = argparse.ArgumentParser()
parser.add_argument("--ratio", help="ratio of the memory we use for hashtable, max is 100% WSAF",
                    type=float, default=.1)
args = parser.parse_args()
ratio = args.ratio

csv_dataroot = pcap_dataroot.replace('PCAPs','CSVs_r_{}/WS'.format(ratio))
ensure_dir(csv_dataroot)

parser = argparse.ArgumentParser()

executable_dir= '../../build/install/SampleMeter/bin'
os.chdir(executable_dir)
def execute(cmd):
    print('\n-------------------')
    print(cmd)
    os.system(cmd)

cmds = []
counter=0
flush_interval_in_sec = 1
for pcap_file in glob(join(pcap_dataroot,'*.pcap')):
    print(pcap_file)
    if 1==1: 
        #pcap_dir = ntpath.split(pcap_file)[0]
        pcap_dir = pcap_file.replace('.pcap','')
        output_dir = pcap_dir.replace('PCAPs','CSVs_r_{}/WS'.format(ratio))
        ensure_dir(output_dir)

        baseline_mem = get_max_wsaf(ntpath.basename(pcap_dir))
        LRU_cache_size = round(baseline_mem*ratio)

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
    

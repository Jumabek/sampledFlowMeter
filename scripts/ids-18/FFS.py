import os
from glob import glob
from os.path import join
from labeler import label_ids_2018, move_out, move_pkt_cnt
import time
import ntpath
import argparse
from multiprocessing import Process

from utils import ensure_dir, get_max_cf, get_max_wsaf
from utils import write_labeldist, write_flow_obsr


#pcap_dataroot = '/media/juma/data/research/intrusion_detection/dataset/CIC-IDS-2018/PCAPs'
#pcap_dataroot = '/home/juma/data/net_intrusion/CIC-IDS-2018/PCAPs'
pcap_dataroot = '/data/juma/data/ids18/PCAPs'

parser = argparse.ArgumentParser()
parser.add_argument("--ratio", help="ratio of the memory we use for hashtable, max is 100% WSAF",
                    type=float, default=1.)
parser.add_argument('--lc', help='size of the linear counter array_size in Mb E: 0.2Mb=> counter array of 52429 where single counter uses 4 byte', type=int,default=1.)
args = parser.parse_args()
ratio = args.ratio
s=8
l=16
sampling_interval =40
sampling_rate = 1

csv_dataroot = pcap_dataroot.replace('PCAPs','CSVs_r_{}_m_{}/SR_{:.1f}/FFS_({},{},{})'.format(ratio,args.lc, sampling_rate,s,l,sampling_interval))

executable_dir = '../../build/install/SampleMeter/bin'
os.chdir(executable_dir)
def execute(cmd):
    print('\n-------------------')
    os.system(cmd)

cmds = []
for pcap_file in glob(join(pcap_dataroot,'*.pcap')):
        pcap_dir = pcap_file.replace('.pcap','')
        output_dir = pcap_dir.replace(pcap_dataroot,csv_dataroot)
        ensure_dir(output_dir)

        LC_size = int(args.lc*1024*1024/4)
        baseline_mem = get_max_wsaf(ntpath.basename(pcap_dir))
        LRU_cache_size = round(baseline_mem*ratio)

        cmd = './SampleMeterMemLimitedCMD "{}" "{}" {} FFS {} {} {} {} {}'.format(pcap_file,output_dir, sampling_rate, LRU_cache_size,sampling_interval, LC_size, s, l)
        print(cmd)
        cmds.append(cmd)


if "sample"=='sample':
    tick = time.time()

    procs = [ Process(target=execute, args=[cmd]) for cmd in cmds]
    for p in procs: p.start()
    for p in procs: p.join()

    tock = time.time()
    sampling_time = int(tock-tick)
    print("Sampling time: {} sec".format(sampling_time))
    with open(join(csv_dataroot,'sampling_time.txt'),'w') as f:
        f.write(str(sampling_time))

if "label"=='label':
        move_out(csv_dataroot)

        #labeling
        tick = time.time()
        label_ids_2018(csv_dataroot)
        tock = time.time()
        print("Labeling time: {} sec".format(tock-tick))
        move_pkt_cnt(csv_dataroot)
        write_labeldist(csv_dataroot+'_l')
        write_flow_obsr(csv_dataroot+'_l')


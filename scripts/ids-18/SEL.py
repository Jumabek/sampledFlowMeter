import os
from glob import glob
from os.path import join
from multiprocessing import Pool
from labeler import label_ids_2018,move_out
import time
import ntpath
from utils import ensure_dir, get_immediate_subdirs
from utils import get_max_cf, get_max_wsaf
import argparse

#pcap_dataroot = '/media/juma/data/research/intrusion_detection/dataset/CIC-IDS-2018/PCAPs'
#pcap_dataroot = '/home/juma/data/net_intrusion/CIC-IDS-2018/PCAPs'
pcap_dataroot = '/data/juma/data/ids18/PCAPs'

# SEL sampling prob 
# p = c         if x<=c
# p = z/(n*x)   if x>c
z,c,n = (10000,0.5,1.9)
sampler_dir = 'SR_10'

parser = argparse.ArgumentParser()
parser.add_argument("--ratio", help="ratio of the memory we use for hashtable, max is 100% WSAF",
                    type=float, default=1.0)
args = parser.parse_args()
ratio=args.ratio

LC_ratio =1./4 
csv_dataroot = pcap_dataroot.replace('PCAPs','CSVs_r_{}/{}/SEL_({},{},{})'.format(ratio,sampler_dir,z,c,n))

executable_dir = '../../build/install/SampleMeter/bin'
os.chdir(executable_dir) # change current working directory
def execute(cmd):
    print('\n---------------------------')
    os.system(cmd)

subdirs = get_immediate_subdirs(pcap_dataroot)
#print(subdirs)

cmds = []
#for d in subdirs:
#    for pcap_path in glob.glob(join(pcap_dataroot,d,'*')):
#        pcap_dir,pcap_file = ntpath.split(pcap_path)
for pcap_file in glob(join(pcap_dataroot,'*.pcap')):
        pcap_dir = pcap_file.replace('.pcap','')
        output_dir = pcap_dir.replace(pcap_dataroot,csv_dataroot)
        ensure_dir(output_dir)
        
        LC_size  = int(int(get_max_cf(ntpath.basename(pcap_dir)))*LC_ratio)

        baseline_mem = get_max_wsaf(ntpath.basename(pcap_dir))
        print(baseline_mem)

        LRU_cache_size = round(baseline_mem*ratio)
        cmd = './SampleMeterMemLimitedCMD "{}" "{}" SEL {} {} {} {} {}'.format(pcap_file,output_dir,LRU_cache_size,z,c,n,LC_size)
        #print(cmd)
        cmds.append(cmd)

tick = time.time()
for cmd in cmds:
    execute(cmd)
tock = time.time()
sampling_time = int(tock - tick)#80min for z=3000
print("Sampling time: {} sec".format(sampling_time))
with  open(join(csv_dataroot,'sampling_time.txt'),'w') as f:
    f.write(str(sampling_time))

move_out(csv_dataroot)

#labeling
tick = time.time()
label_ids_2018(csv_dataroot)
tock = time.time()
print("Labeling time: {} sec".format(tock-tick))

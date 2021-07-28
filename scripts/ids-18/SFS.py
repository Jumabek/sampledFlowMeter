import os
from os.path import join
import ntpath
import math
import time
from glob import glob
import argparse
import ntpath
from multiprocessing import Process 

from labeler import label_ids_2018, move_out, move_pkt_cnt
from utils import ensure_dir
from utils import get_max_wsaf, get_max_cf
from utils import write_labeldist, write_flow_obsr


def round_up(n, decimals=0):
    multiplier = 10 ** decimals
    return math.ceil(n * multiplier) / multiplier

layer1 = {}
layer1[0]=  1
layer1[1]=  2.14285659790039
layer1[2]=  3.48760619663446
layer1[3]=  5.11604451868295
layer1[4]=  7.15183056968443
layer1[5]=  9.76362232845268  # setting 5/8 % ones trigger saturation will result 9.76 sampling interval
layer1[6]=  13.1804311589001
layer1[7]=  18.0749365561602

layer2 = {num_ones:sampling_interval**2 for num_ones,sampling_interval in layer1.items()}
# {0: 1,
#  1: 4.591834399165235,
#  2: 12.163396982803082,
#  3: 26.17391151714586,
#  4: 51.14868049747272,
#  5: 95.32832097265972,
#  6: 173.72376553450465,
#  7: 326.70333150921635}

layer3 = {num_ones:sampling_interval**3 for num_ones,sampling_interval in layer1.items()}
# {0: 1,
#  1: 9.839642638717196,
#  2: 42.42113868934892,
#  3: 133.90689654978664,
#  4: 365.8066967808472,
#  5: 930.7497231825645,
#  6: 2289.7541322924403,
#  7: 5905.141989715259}

layer4 = {num_ones:sampling_interval**4 for num_ones,sampling_interval in layer1.items()}
# {0: 1,
#  1: 21.08494314935715,
#  2: 147.94822616126314,
#  3: 685.0736441073808,
#  4: 2616.187516632546,
#  5: 9087.488779466437,
#  6: 30179.946711487544,
#  7: 106735.06681922091}

#pcap_dataroot = '/media/juma/data/research/intrusion_detection/dataset/CIC-IDS-2018/PCAPs'
#pcap_dataroot = '/home/juma/data/net_intrusion/CIC-IDS-2018/PCAPs'
pcap_dataroot = '/data/juma/data/ids18/PCAPs'
parser = argparse.ArgumentParser()
parser.add_argument("--ratio", help="ratio of the memory we use for hashtable, max is 100% WSAF",
                    type=float, default=1.)
parser.add_argument('--lc', help='size of the linear counter array_size in Mb E: 0.2Mb=> counter array of 52429 where single counter uses 4 byte', type=int,default=1.)
args = parser.parse_args()
ratio = args.ratio
num_of_layers = 2
num_of_ones = 5
sampling_interval = layer1[num_of_ones]**num_of_layers
NUM_OF_CORES= 8
sampling_rate = 1
#sampler_dir = 'SR_1.0'

csv_dataroot = pcap_dataroot.replace('PCAPs','CSVs_r_{}_m_{}/SR_{:.1f}/SFS_SI_{}'.format(ratio,args.lc,sampling_rate,round_up(sampling_interval,2)))

executable_dir = '../../build/install/SampleMeter/bin'
os.chdir(executable_dir) # change current working directory
def execute(cmd):
    print("\n-------------------------")
    os.system(cmd)

cmds = []
for pcap_file in glob(join(pcap_dataroot,'*.pcap')):
        pcap_dir = pcap_file.replace('.pcap','')
        output_dir = pcap_dir.replace(pcap_dataroot,csv_dataroot)
        ensure_dir(output_dir)

        LC_size = int(args.lc*1024*1024/4) # convert Mb to Bytes and divide by 4 since integer has 4 bytes
        baseline_mem = get_max_wsaf(ntpath.basename(pcap_dir))
        LRU_cache_size = round(baseline_mem*ratio)
        
        cmd = './SampleMeterMemLimitedCMD "{}" "{}" {} SFS {} {} {} {} {}'.format(pcap_file,output_dir,sampling_rate, LRU_cache_size,sampling_interval, LC_size, num_of_layers, num_of_ones)
        cmds.append(cmd)
tick = time.time()

if "Sample"=="Sample":
    procs = [ Process(target=execute, args=[cmd]) for cmd in cmds]
    for p in procs: p.start()
    for p in procs: p.join()

    tock = time.time()
    delta = int(tock - tick)
    print("Sampling time: {0:.2f}".format(delta))
    with open(join(csv_dataroot,'sampling_time.txt'),'w') as f:
        f.write(str(delta))

if "label"=='label':
    move_out(csv_dataroot)

    #labeling
    tick = time.time()
    label_ids_2018(csv_dataroot)
    tock = time.time()
    print("For labeling it took {} sec".format(tock-tick))
    move_pkt_cnt(csv_dataroot)
    write_labeldist(csv_dataroot+'_l')
    write_flow_obsr(csv_dataroot+'_l')
    

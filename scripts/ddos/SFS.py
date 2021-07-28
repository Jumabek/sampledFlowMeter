import math
import os
from labeler import label_ddos_test
import time
import ntpath
from utils import ensure_dir, get_max_num_concurrent_flows_test
from utils import get_ddos_test_baseline_mem
from os.path import join

def round_up(n, decimals=0):
    multiplier = 10 ** decimals
    return math.ceil(n * multiplier) / multiplier

#pcap_dataroot = '/media/juma/data/research/intrusion_detection/dataset/CIC-IDS-2018/PCAPs'
pcap_dataroot = '/data/juma/data/ddos/PCAPs/PCAP-03-11'

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


num_of_layers =1
num_of_ones = 1
sampling_interval = layer1[num_of_ones]**num_of_layers
NUM_OF_CORES= 8
SR = 100/sampling_interval 
sampler_dir = 'SR_{}'.format(round(SR,2))

executable_dir = '../../build/install/SampleMeter/bin'
os.chdir(executable_dir)

def execute(cmd):
    print(cmd)
    os.system(cmd)

for i in range(1):
    ratio = 1./10**i
    print("ratio ",ratio)    
    csv_dataroot = pcap_dataroot.replace('PCAPs','CSVs_r_{}/{}/SFS_SI_{}'.format(ratio,sampler_dir,round_up(sampling_interval,2)))
    #sampling
    LC_size = get_max_num_concurrent_flows_test()//4 # that is biggest memory fo SFS
    LRU_cache_size = int(ratio*get_ddos_test_baseline_mem())
    cmd = './SampleMeterMemLimitedCMD "{}" "{}" SFS {} {} {} {} {}'.format(pcap_dataroot,csv_dataroot,LRU_cache_size,sampling_interval, LC_size, num_of_layers, num_of_ones)
    print("Sampling")

    tick = time.time()
    #execute(cmd)
    tock = time.time()

    ensure_dir(csv_dataroot+'_l')
    with open(join(csv_dataroot+'_l','sampling_time.txt'),'w') as f:
        f.write('{:.0f}'.format(tock-tick))

    #labeling
    label_ddos_test(csv_dataroot)

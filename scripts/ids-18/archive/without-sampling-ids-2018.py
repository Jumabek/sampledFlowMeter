import os
from os.path import join
from multiprocessing import Pool
from labeler import label_ids_2018, merge
import ntpath
import time
from utils import get_immediate_subdirs, ensure_dir
from utils import get_executables_dir
from utils import get_threshold

#dataroot = '/media/juma/data/research/intrusion_detection/dataset/CIC-IDS-2018/PCAPs'
dataroot = '/home/juma/data/net_intrusion/CIC-IDS-2018/PCAPs'

def execute(cmd):
    print(cmd)
    os.system(cmd)

subdirs = get_immediate_subdirs(dataroot)
print(subdirs)

cmds = []
counter=0
for d in subdirs:
    for pcap_filename in os.listdir(join(dataroot,d)):
        pcap_file = join(dataroot,d,pcap_filename)
        pcap_dir = ntpath.split(pcap_file)[0]
        output_dir = pcap_dir.replace('PCAPs','CSVs/without_sampling')
        ensure_dir(output_dir)
        cmd = './cfm "{}" "{}" NS'.format(pcap_file,output_dir)
        cmds.append(cmd)
        counter+=1
        print("#{:2} {:70} - {:20}".format(counter,pcap_file,os.path.getsize(pcap_file)))

os.chdir(get_executables_dir()) # change current working directory
exit(1)
# multi-processing
p = Pool(processes=6)
tick = time.time()
p.map(execute,cmds)
tock = time.time()
print("TOTAL Time it took for sampling: {:0.f}  ",(tock-tick)/60.)

#merging
tick = time.time()
merge(dataroot.replace('PCAPs','CSVs/without_sampling'))
tock = time.time()
print("Merging time {:.0f} minutes".format((tock-tick)/60.))

#labeling
tick = time.time()
label_ids_2018(dataroot.replace('PCAPs','CSVs/without_sampling'))
tock = time.time()
print("Time take for labeling {:.0f} min".format((tock-tick)/60.))

#scripts removes pcaps with different day
#remove other days

from glob import glob
import os
from os.path import join
import ntpath
from multiprocessing import Process


#dataroot = '/data/juma/data/ids18/PCAPs/Thursday-15-02-2018/'
dataroot = '/mnt/disk3/net_intrusion/ids18/PCAPs/'

def execute(cmd):
    print('------------')
    os.system(cmd)


def is_on_2018(str_output):
    return str_output.count('2018-')==2


for fn in tqdm(glob(join(dataroot,'*'))):
    output = subprocess.run(['capinfos','-a','-e',fn], stdout=subprocess.PIPE)
    str_output = str(output.stdout, 'utf-8')
    if is_on_2018(str_output):
        dest_fn = fn.replace(dataroot, output_root)
        os.rename(fn,dest_fn)



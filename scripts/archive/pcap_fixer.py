from glob import glob
import os
from os.path import join
import ntpath
from multiprocessing import Process


#dataroot = '/data/juma/data/ids18/PCAPs/Thursday-15-02-2018/'
dataroot = '/mnt/disk3/net_intrusion/ids18/traffic/Friday-02-03-2018/pcap'
output_root = '/mnt/disk3/net_intrusion/ids18/traffic/Friday-02-03-2018/temp_fixed'
os.makedirs(output_root)

def execute(cmd):
    print('------------')
    os.system(cmd)


#Step I: fix pcaps     
cmds = []
for fn in glob(join(dataroot,'*')):
    outfile = fn.replace(dataroot, output_root)
    print(fn,' => ',outfile)
    cmd= '../../pcapfix/pcapfix -s "{}" -o "{}"'.format(fn,outfile)
    cmds.append(cmd)    
    

procs = [ Process(target=execute, args=[cmd]) for cmd in cmds]
for p in procs: p.start()
for p in procs: p.join()
 
exit()

print('replace fixed pcaps with noisy ones')
for fn in glob(join(dataroot,'temp_fixed_pcap/*')):
    print(ntpath.basename(fn))
    outfile = fn.replace('temp_fixed_pcap','pcap')#.replace('/pcap','') # same output file
    # remove first corrupted pcap
    os.remove(outfile)
    # move fixed pcap
    os.rename(fn,outfile)

#Step II: remove pcaps which has different days
# verify if this is not happening due to side effect of Step I

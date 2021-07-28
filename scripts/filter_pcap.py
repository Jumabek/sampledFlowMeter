from glob import glob
import os
from os.path import join
import ntpath
from multiprocessing import Process, Pool
import time
from tqdm import tqdm

def execute(cmd):
    #print(cmd)
    os.system(cmd)

def makedir(d):
    if not os.path.isdir(d):
        os.makedirs(d)

result_list = []
def log_result(result):
    # This is called whenever foo_pool(i) returns a result.
    # result_list is modified only by the main process, not the pool workers.
    result_list.append(result)
days = {
'Friday-16-02-2018':('02-16','02-18')}

days1 = {
'Friday-16-02-2018':('02-16','02-18'),
'Friday-23-02-2018':('02-23','02-25'),
'Thursday-01-03-2018': ('03-01','03-03'),
'Thursday-15-02-2018':('02-15','02-17'),
'Thursday-22-02-2018':('02-22','02-24'),
'Tuesday-20-02-2018':('02-20','02-22'),
'Wednesday-14-02-2018':('02-14','02-16'),
'Wednesday-21-02-2018':('02-21','02-23'),
'Wednesday-28-02-2018':('02-28','03-02')
}

dataroot_regex = '/data/juma/data/ids18/PCAPs/{}/pcap'
pcapfix_regex = '/data/juma/data/ids18/PCAPs/{}/pcapfix'
editcap_regex = '/data/juma/data/ids18/PCAPs/{}/editcap'

for day, (begin_time, end_time) in days.items():
    tick = time.time()

    #Step I fix, packet w/ problem. E: cut in the middle 
    dataroot  = dataroot_regex.format(day)
    pcapfix_root = pcapfix_regex.format(day)
    makedir(pcapfix_root)
    #pcapfix
    cmds = []
    for fn in sorted(glob(join(dataroot,'*'))):
        outfile = fn.replace(dataroot, pcapfix_root)
        cmd= '../../pcapfix/pcapfix -s "{}" -o "{}"'.format(fn,outfile)
        cmds.append(cmd)
        #execute(cmd)
    with Pool() as p:
        p.map(execute, cmds)
        p.close()
        p.join()
    # moving process. 
    for fn in tqdm(glob(join(pcapfix_root,'*'))):
        outfile = fn.replace(pcapfix_root, dataroot)
        os.rename(fn, outfile)
    #Step II: remove packets w/ problem. Heuristic is they are not in the given DATE range 
#editcap
    editcap_root = editcap_regex.format(day)
    makedir(editcap_root)
    for fn in sorted(glob(join(dataroot,'*'))):
        outfile = fn.replace(dataroot, editcap_root)
        cmd= 'editcap  -A "2018-{} 21:00:00" -B "2018-{} 00:00:00" "{}" "{}"'.format(begin_time, end_time, fn,outfile)
        execute(cmd)
  
    print("pcapfix and editcap in {:.2f}".format(time.time()-tick))
    # mp: pool vs async, (246 files) 358 sec vs (243q files)  243 sec

    # seq (246 files): 212 sec
# Step III merging part
cmds = []
for day in days.keys():
    print(day)
    editcap_root = editcap_regex.format(day)
    print("mergecap")
    outfile = join('/data/juma/data/ids18/PCAPs','{}.pcap'.format(day))
    os.chdir(editcap_root)
    fns = [i for i in glob('*')]
    cmd = 'mergecap  -w {} {} -F pcap'.format(outfile, ' '.join('"{0}"'.format(w) for w in fns))
    os.system(cmd)
    #cmds.append(cmd)    

tick = time.time()
with Pool() as p:
    p.map(execute, cmds)
    p.close()
    p.join()
 
print("Merged in {:.2f}".format(time.time()-tick))# 40min



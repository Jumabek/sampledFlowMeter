import os
from glob import glob
import pandas as pd
from os.path import join
from datetime import datetime
from multiprocessing import Pool, Manager, Lock, Process
import ntpath
import pytz
from collections import defaultdict
from utils import ensure_dir, get_immediate_subdirs
from utils import get_dtype
import time

#currently used for saving label_dist
def save_dict_to_csv(filename,d):
        with open(filename,'w') as f:
            for key in sorted(d.keys()):
                f.write('{},{}\n'.format(key,d[key]))

#during feature extraction (w/ sampling) pcap-day-folder is given as output destinination: which stores  Cache Utilization log, sampled packet count, kickout count, early kickout count in addition to flowrecords

def move_out(dataroot):
    print("Moving out")
    folders = get_immediate_subdirs(dataroot)
    for folder in folders:
        outfile = join(dataroot,folder+'_TrafficForML_CICFlowMeter.csv')
        filenames = [fn for fn in glob(join(dataroot,folder,'*.pcap_Flow.csv'))]
        assert len(filenames)<2, "MovingOut: Multiple flowrecords file in {}".format( folder)
        print("{} ==>> {}".format(folder,ntpath.basename(outfile)))
        os.rename(filenames[0],outfile)


def move_pkt_cnt(dataroot):
    pkt_cnt = 0
    for fn in glob(join(dataroot,'*/*.pcap_SPC.txt')):
        with open(fn) as f:
            pkt_cnt+= int(f.readline())
    with open(join(dataroot+'_l','num_pkt.txt'), 'w') as f:
        f.write('{}\n'.format(pkt_cnt))


def merge(dataroot):
    folders = get_immediate_subdirs(dataroot)
    for folder in folders:
        filenames = [i for i in glob(join(dataroot,folder,'*.pcap_Flow.csv'))]
        print("merging folder: ",folder)
        df_l =[pd.read_csv(f,encoding='utf-8-sig', engine='python') for f in filenames]
        if len(df_l)<1:
            print("There isnt any CSV file")
            continue
        
        combined_csv = pd.concat(df_l,sort=False)
        combined_csv.to_csv(join(dataroot,folder+'_TrafficForML_CICFlowMeter.csv'),index=False,encoding='utf-8-sig')
        
        #now merge the counts.
        filenames = [i for i in glob(join(dataroot,folder,"*pcap_SPC.txt"))]
        counts = [int(open(f).readline()) for f in filenames]
        with  open(join(dataroot+'_l',folder+".pcap_SPC.txt"),"w") as f1:
            f1.write("{}\n".format(sum(counts)))
        print('+++++++++++++++++++')


def label_df(data,attackers, victims, attack_time, attack_names):
    data['Label']='Benign'
    date_format = '%d/%m/%Y %I:%M:%S %p'
    # java format "dd/MM/yyyy hh:mm:ss a"
    ds_timesampt = pd.to_datetime(data['Timestamp'],format=date_format)
    attack_dt_format = '%d/%m/%Y %I:%M:%S %p'
    for ttx, attack_name in enumerate(attack_names):
        begin_time = datetime.strptime(attack_time[ttx][0],attack_dt_format)
        end_time = datetime.strptime(attack_time[ttx][1],attack_dt_format)

        for attacker in attackers[ttx]:
            for victim in victims[ttx]:
                    attacker_flow1 = (data['Dst IP']==attacker) & (data['Src IP']==victim)
                    attacker_flow2 = (data['Src IP']==attacker)&(data['Dst IP']==victim)
                    attacker_flow = attacker_flow1 | attacker_flow2
                        
                    before = ds_timesampt>=begin_time
                    after = ds_timesampt<= end_time
                    data.loc[attacker_flow & before & after, 'Label'] = attack_name
    return data


def label_flows_bidirectionally(filename,outputname,attackers, victims, attack_time, attack_names):
    if not os.path.isfile(filename):
        print('There is no file with {} name'.format(filename))
        print('skipping labeling')
        return None
    else:
        print("Labeling ",filename)

    # we chunk the data to be able to process large CSV filed (eg: 7.5G )   
    chunk_size = 10**6
    maximum_rows = 10**8
    n_chunks = maximum_rows//chunk_size

    column_names = []
    local_label_dist = defaultdict(lambda:0)
    for i in range(n_chunks):
        tick = time.time()
        seen_so_far = i*chunk_size
        print(i)
        if i==0:
            data = pd.read_csv(filename,encoding='utf-8-sig', engine='c',dtype=get_dtype(),nrows=chunk_size)
            column_names = data.columns
        else:
            data = pd.read_csv(filename,encoding='utf-8-sig', engine='c',dtype=get_dtype(),nrows=chunk_size,skiprows=seen_so_far, header=0,names=column_names)
            if data.shape[0]<1:
                break
        data = label_df(data,attackers,victims, attack_time, attack_names)
        if i==0:
            data.to_csv(outputname,index=False,encoding='utf-8-sig')
        else:
            data.to_csv(outputname,index=False,encoding='utf-8-sig',mode='a',header=None)
            
        label_dist_i = data.Label.value_counts()
        for key in label_dist_i.keys():
            local_label_dist[key]+=label_dist_i[key] 
        tock = time.time()
        print("df.shape = ", data.shape)
        print("processed in : ",tock-tick)

    print("label distribtion for {}".format(ntpath.basename(filename)))
    print(local_label_dist)
    print()
    
    return local_label_dist


def label_ids_2018(dataroot):
    outputroot = dataroot + '_l'
    if not os.path.exists(outputroot):
         os.makedirs(outputroot)
    if 1==1:
        args_list = [] # one for each day.

        #Day 1
        attack_names = ['FTP-BruteForce','SSH-BruteForce']
        attackers = [['18.221.219.4'], ['13.58.98.64']]
        victims = [['172.31.69.25'],['172.31.69.25']]

        attack_times = [['14/02/2018 10:32:00 AM','14/02/2018 12:10:31 PM'],
                   ['14/02/2018 02:01:00 PM','14/02/2018 03:32:30 PM']]

        filename = join(dataroot,'Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv')
        outputname = join(outputroot,'Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv')  
        args = (filename,outputname, attackers, victims, attack_times, attack_names)
        args_list.append(args)

        #Day 2        
        attack_names = ['DoS-GoldenEye','DoS-Slowloris']
        attackers = [['18.219.211.138'], ['18.217.165.70']]
        victims = [['172.31.69.25'],
            ['172.31.69.25']]
        attack_times = [['15/02/2018 09:27:42 AM','15/02/2018 10:11:45 AM'],
                       ['15/02/2018 10:59:00 AM','15/02/2018 11:42:01 AM']]
        #attack_times = [['15/02/2018 09:26:00 AM','15/02/2018 10:09:59 AM'],
        #               ['15/02/2018 10:59:00 AM','15/02/2018 11:42:01 AM']]
        
        filename = join(dataroot,'Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv')
        outputname = join(outputroot,'Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv')   
        args = (filename,outputname, attackers, victims, attack_times, attack_names)
        args_list.append(args)

        #Day3
        attack_names = ['DoS-SlowHTTPTest','DoS-Hulk']
        attackers = [['13.59.126.31'], ['18.219.193.20']]
        victims = [['172.31.69.25'],['172.31.69.25']]
        
        attack_times = [['16/02/2018 10:12:00 AM','16/02/2018 11:08:59 AM'],
                       ['16/02/2018 01:45:00 PM','16/02/2018 02:19:59 PM']]
        
        filename = join(dataroot,'Friday-16-02-2018_TrafficForML_CICFlowMeter.csv')
        outputname = join(outputroot,'Friday-16-02-2018_TrafficForML_CICFlowMeter.csv') 
        args = (filename,outputname, attackers, victims, attack_times, attack_names)
        args_list.append(args)

        #Day 4
        attack_names = ['DDoS-LOIC-HTTP','DDoS-LOIC-UDP']
        attackers = [['18.218.115.60',
                            '18.219.9.1',
                            '18.219.32.43',
                            '18.218.55.126',
                            '52.14.136.135',
                            '18.219.5.43',
                            '18.216.200.189',
                            '18.218.229.235',
                            '18.218.11.51',
                            '18.216.24.42'], 
                         ['18.218.115.60',
                            '18.219.9.1',
                            '18.219.32.43',
                            '18.218.55.126',
                            '52.14.136.135',
                            '18.219.5.43',
                            '18.216.200.189',
                            '18.218.229.235',
                            '18.218.11.51',
                            '18.216.24.42']]
        victims = [['172.31.69.25'],
        ['172.31.69.25']]
        
        attack_times = [['20/02/2018 10:12:00 AM','20/02/2018 11:17:59 AM'],
                       ['20/02/2018 01:13:00 PM','20/02/2018 01:32:59 PM']]
        
        filename = join(dataroot,'Tuesday-20-02-2018_TrafficForML_CICFlowMeter.csv')
        outputname = join(outputroot,'Tuesday-20-02-2018_TrafficForML_CICFlowMeter.csv')    
        args = (filename,outputname, attackers, victims, attack_times, attack_names)
        args_list.append(args)

        #Day 5
        attack_names = ['DDoS-LOIC-UDP','DDoS-HOIC']
        attackers = [['18.218.115.60',
                            '18.219.9.1',
                            '18.219.32.43',
                            '18.218.55.126',
                            '52.14.136.135',
                            '18.219.5.43',
                            '18.216.200.189',
                            '18.218.229.235',
                            '18.218.11.51',
                            '18.216.24.42'], 
                         ['18.218.115.60',
                            '18.219.9.1',
                            '18.219.32.43',
                            '18.218.55.126',
                            '52.14.136.135',
                            '18.219.5.43',
                            '18.216.200.189',
                            '18.218.229.235',
                            '18.218.11.51',
                            '18.216.24.42']]
        victims = [['172.31.69.28'],['172.31.69.28']]
        attack_times = [['21/02/2018 10:08:50 AM','21/02/2018 10:43:59 AM'],
                       ['21/02/2018 02:05:00 PM','21/02/2018 03:05:59 PM']]
        
        filename = join(dataroot,'Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv')
        outputname = join(outputroot,'Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv')  
        args = (filename,outputname, attackers, victims, attack_times, attack_names)
        args_list.append(args)

        #Day 6
        attack_names = ['Brute Force-Web','Brute Force-XSS','SQL Injection']
        attackers = [['18.218.115.60'], 
                         ['18.218.115.60'],
                         ['18.218.115.60']]
        victims = [['172.31.69.28'],
                  ['172.31.69.28'],
                  ['172.31.69.28']]
        
        attack_times = [['22/02/2018 10:17:00 AM','22/02/2018 11:24:59 AM'],
                       ['22/02/2018 01:50:00 PM','22/02/2018 02:29:59 PM'],
                       ['22/02/2018 04:15:00 PM','22/02/2018 04:29:59 PM']]
        
        filename = join(dataroot,'Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv')
        outputname = join(outputroot,'Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv')   
        args = (filename,outputname, attackers, victims, attack_times, attack_names)
        args_list.append(args)

        #Day 7
        attack_names = ['Brute Force-Web','Brute Force-XSS','SQL Injection']
        attackers = [['18.218.115.60'], 
                         ['18.218.115.60'],
                         ['18.218.115.60']]

        victims = [['172.31.69.28'],
                   ['172.31.69.28'],
                   ['172.31.69.28']]

        attack_times = [['23/02/2018 10:03:00 AM','23/02/2018 11:03:59 AM'],
                       ['23/02/2018 01:00:00 PM','23/02/2018 02:10:59 PM'],
                       ['23/02/2018 03:05:00 PM','23/02/2018 03:18:59 PM']]
        
        filename = join(dataroot,'Friday-23-02-2018_TrafficForML_CICFlowMeter.csv')
        outputname = join(outputroot,'Friday-23-02-2018_TrafficForML_CICFlowMeter.csv') 
        args = (filename,outputname, attackers, victims, attack_times, attack_names)
        args_list.append(args)

        #Day 8
        attack_names = ['Infiltration','Infiltration']
        # flipping attacker and victims IPs
        victims = [['13.58.225.34'], 
                         ['13.58.225.34']]
        attackers = [['172.31.69.24'],
            ['172.31.69.24']]
        
        attack_times = [['28/02/2018 10:50:00 AM','28/02/2018 12:05:59 PM'],
                       ['28/02/2018 01:42:00 PM','28/02/2018 02:40:59 PM']]
        
        filename = join(dataroot,'Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv')
        outputname = join(outputroot,'Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv')  
        args = (filename,outputname, attackers, victims, attack_times, attack_names)
        args_list.append(args)

        # Day 9
        attack_names = ['Infiltration','Infiltration']
        # flipping attacker and victims IPs
        victims = [['13.58.225.34'], 
                         ['13.58.225.34']]
        attackers = [['172.31.69.13'],
                      ['172.31.69.13']]
        attack_times = [['01/03/2018 09:57:00 AM','01/03/2018 10:55:59 AM'],
                       ['01/03/2018 02:00:00 PM','01/03/2018 03:37:59 PM']]
        
        filename = join(dataroot,'Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv')
        outputname = join(outputroot,'Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv')   
        args = (filename,outputname, attackers, victims, attack_times, attack_names)
        args_list.append(args)

        # Day 10
        attack_names = ['Bot','Bot']

        attackers = [['18.219.211.138'],
                     ['18.219.211.138']]

        victims =[
            ['172.31.69.23',
             '172.31.69.17',
             '172.31.69.14',
             '172.31.69.12',
             '172.31.69.10',
             '172.31.69.8',
             '172.31.69.6',
             '172.31.69.26',
             '172.31.69.29',
             '172.31.69.30'],
            ['172.31.69.23',
             '172.31.69.17',
             '172.31.69.14',
             '172.31.69.12',
             '172.31.69.10',
             '172.31.69.8',
             '172.31.69.6',
             '172.31.69.26',
             '172.31.69.29',
             '172.31.69.30']]

        attack_times = [
            ['02/03/2018 10:11:00 AM','02/03/2018 11:34 AM'],
            ['02/03/2018 02:24:00 PM','02/03/2018 03:55 PM']
        ]

        filename = join(dataroot,'Friday-02-03-2018_TrafficForML_CICFlowMeter.csv')
        outputname = join(outputroot,'Friday-02-03-2018_TrafficForML_CICFlowMeter.csv')
        #args = (filename,outputname, attackers, victims, attack_times, attack_names,label_dist,lock)
        #args_list.append(args)
        


        # #MP with map
        #p = Pool(9)
        #p.map(label_flows_bidirectionally,args_list)
        
        # MP with Process
        procs = [Process(target=label_flows_bidirectionally,args=arguments) for arguments in args_list]
        
        for p in procs: p.start()
        for p in procs: p.join()


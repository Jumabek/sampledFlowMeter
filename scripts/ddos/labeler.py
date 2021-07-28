import os
import glob
import pandas as pd
from os.path import join
from datetime import datetime
import ntpath
import pytz
from collections import defaultdict
import time

from utils import ensure_dir
from utils import get_dtype
from utils import get_cols4labeling, get_dtype

#currently used for saving label_dist
def save_dict_to_csv(filename,d):
        with open(filename,'w') as f:
            for key in sorted(d.keys()):
                f.write('{},{}\n'.format(key,d[key]))


def label_attack(data,attacker,victim, schedule, attack_name,outputroot):
    #we assume data is sorted by timestamp(and time stamp is already parsed)
    attack_dt_format = '%d/%m/%Y %I:%M %p' # note 'I' forces parser to consider AM/PM formats
    start,end = schedule
    begin_time = datetime.strptime(start,attack_dt_format)
    end_time = datetime.strptime(end,attack_dt_format)
    print('{}: [{} - {}]'.format(attack_name, begin_time, end_time))
    
    #selecting by IP
    attacker_flow1 = (data['Dst IP']==attacker) & (data['Src IP']==victim)
    attacker_flow2 = (data['Src IP']==attacker)&(data['Dst IP']==victim)
    attacker_flow = attacker_flow1 | attacker_flow2
    
    after = data['Timestamp'] >= begin_time
    before = data['Timestamp'] < end_time
    outside = data['Timestamp'] >=end_time    

    #labeling the selection
    data.loc[attacker_flow & before & after, 'Label'] = attack_name
    df_in_range = data.loc[before & after]
    df_in_range.to_csv(join(outputroot,attack_name+'.csv'),encoding='utf-8-sig',index=False)
    label_dist = df_in_range.Label.value_counts()
    return data.loc[outside],label_dist # only return the data which is captured later than current attack


# test Jan 12, 2018
def label_ddos_test(dataroot):
    outputroot = dataroot + '_l'
    if not os.path.exists(outputroot):
        os.makedirs(outputroot)
   
    n = 10000
    data = pd.read_csv(join(dataroot,'Records_Flow.csv'),usecols=get_cols4labeling(),dtype=get_dtype())
    #data = pd.read_csv(join(dataroot,'Records_Flow.csv'),dtype=get_dtype(),skiprows=lambda x: x%n!=0)
    data['Label']='Benign' # default is benign

    # java format "dd/MM/yyyy hh:mm:ss a"
    date_format = '%m/%d/%Y %I:%M:%S %p'
    data['Timestamp'] = pd.to_datetime(data['Timestamp'],format=date_format)
    data.sort_values(by=['Timestamp'])

    attacker = '172.16.0.5'
    victim = '192.168.50.4'
    
    label_dist = defaultdict(lambda:0)

    attack_name='PortMap'
    schedule = ('11/03/2018 09:43 AM','11/03/2018 09:51 AM')
    data,local_label_dist = label_attack(data,attacker,victim,schedule,attack_name,outputroot)
    label_dist = add_to_dictionary(label_dist,local_label_dist)

    attack_name='NetBIOS'
    schedule = ('11/03/2018 10:00 AM','11/03/2018 10:09 AM')
    data,local_label_dist = label_attack(data,attacker,victim,schedule,attack_name,outputroot)
    label_dist = add_to_dictionary(label_dist,local_label_dist)

    attack_name='LDAP'
    schedule = ('11/03/2018 10:21 AM','11/03/2018 10:31 AM')
    data,local_label_dist = label_attack(data,attacker,victim,schedule,attack_name,outputroot)
    label_dist = add_to_dictionary(label_dist,local_label_dist)

    attack_name='MSSQL'
    schedule = ('11/03/2018 10:33 AM','11/03/2018 10:42 AM')
    data,local_label_dist = label_attack(data,attacker,victim,schedule,attack_name,outputroot)
    label_dist = add_to_dictionary(label_dist,local_label_dist)

    attack_name='UDP'
    schedule = ('11/03/2018 10:53 AM','11/03/2018 11:03 AM')
    data,local_label_dist = label_attack(data,attacker,victim,schedule,attack_name,outputroot)
    label_dist = add_to_dictionary(label_dist,local_label_dist)

    attack_name='UDP-Lag'
    schedule = ('11/03/2018 11:14 AM','11/03/2018 11:24 AM')
    data, local_label_dist = label_attack(data,attacker,victim,schedule,attack_name,outputroot)
    label_dist = add_to_dictionary(label_dist,local_label_dist)

    attack_name='SYN'
    schedule = ('11/03/2018 11:28 AM','11/03/2018 05:35 PM')
    data,local_label_dist = label_attack(data,attacker,victim,schedule,attack_name,outputroot)
    label_dist = add_to_dictionary(label_dist,local_label_dist)
    
    print("After attack schedules -------------------")
    print(data.Label.value_counts())
    data.to_csv(join(outputroot,'records.csv'),index=False,encoding='utf-8-sig')
    save_dict_to_csv(join(outputroot,'label_dist.csv'),label_dist)


def add_to_dictionary(label_dist,local_label_dist):
    if local_label_dist is not None:
        for key in local_label_dist.keys():
            label_dist[key]+=local_label_dist[key]
    return label_dist


# train Jan 12, 2018
def label_ddos_train(dataroot):
    outputroot = dataroot + '_l'
    if not os.path.exists(outputroot):
        os.makedirs(outputroot)
    print("reading csv file...")
    n = 10000
    tick = time.time()
    data = pd.read_csv(join(dataroot,'Records_Flow.csv'),usecols=get_cols4labeling(),dtype=get_dtype())
    #data = pd.read_csv(join(dataroot,'Records_Flow.csv'),dtype=get_dtype(),skiprows=lambda x: x%n!=0)
    tock = time.time()
    print("Done reading in {} sec".format(tock-tick))
    data['Label']='Benign' # default is benign
    
    # java format "dd/MM/yyyy hh:mm:ss a"
    date_format = '%m/%d/%Y %I:%M:%S %p'
    data['Timestamp'] = pd.to_datetime(data['Timestamp'],format=date_format)
    data.sort_values(by=['Timestamp'])

    

    attacker = '172.16.0.5'
    victim = '192.168.50.1'

    label_dist = defaultdict(lambda:0)

    attack_name='NTP'
    schedule = ('12/01/2018 10:35 AM','12/01/2018 10:45 AM')
    data,local_label_dist = label_attack(data,attacker,victim,schedule,attack_name,outputroot)
    label_dist = add_to_dictionary(label_dist,local_label_dist)
    
    attack_name='DNS'
    schedule = ('12/01/2018 10:52 AM','12/01/2018 11:05 AM')
    data,local_label_dist = label_attack(data,attacker,victim,schedule,attack_name, outputroot)
    label_dist = add_to_dictionary(label_dist,local_label_dist)
   
    attack_name = 'LDAP'
    schedule = ('12/01/2018 11:22 AM','12/01/2018 11:32 AM')
    data,local_label_dist = label_attack(data,attacker,victim,schedule,attack_name, outputroot)
    label_dist = add_to_dictionary(label_dist,local_label_dist)
    
    attack_name = 'MSSQL'
    schedule = ('12/01/2018 11:36 AM','12/01/2018 11:45 AM')
    data,local_label_dist = label_attack(data,attacker,victim,schedule,attack_name,outputroot)
    label_dist = add_to_dictionary(label_dist,local_label_dist)
    
    attack_name = 'NetBIOS'
    schedule = ('12/01/2018 11:50 AM','12/01/2018 12:00 PM')
    data,local_label_dist = label_attack(data,attacker,victim,schedule,attack_name,outputroot)
    label_dist = add_to_dictionary(label_dist,local_label_dist)
    
    attack_name = 'SNMP'
    schedule = ('12/01/2018 12:12 PM','12/01/2018 12:23 PM')
    data,local_label_dist = label_attack(data,attacker,victim,schedule,attack_name, outputroot)
    label_dist = add_to_dictionary(label_dist,local_label_dist)
    

    attack_name = 'SSDP'
    schedule = ('12/01/2018 12:27 PM','12/01/2018 12:37 PM')
    data,local_label_dist = label_attack(data,attacker,victim,schedule,attack_name, outputroot)
    label_dist = add_to_dictionary(label_dist,local_label_dist)
    

    attack_name = 'UDP'
    schedule = ('12/01/2018 12:45 PM','12/01/2018 01:09 PM')
    data,local_label_dist = label_attack(data,attacker,victim,schedule,attack_name, outputroot)
    label_dist = add_to_dictionary(label_dist,local_label_dist)
    

    attack_name = 'UDP-Lag'
    schedule = ('12/01/2018 01:11 PM','12/01/2018 01:15 PM')
    data,local_label_dist = label_attack(data,attacker,victim,schedule,attack_name,outputroot)
    label_dist = add_to_dictionary(label_dist,local_label_dist)
    

    attack_name = 'WebDDoS'
    schedule = ('12/01/2018 01:18 PM','12/01/2018 01:29 PM')
    data ,local_label_dist= label_attack(data,attacker,victim,schedule,attack_name, outputroot)
    label_dist = add_to_dictionary(label_dist,local_label_dist)
    

    attack_name = 'SYN'
    schedule = ('12/01/2018 01:29 PM','12/01/2018 01:34 PM')
    data ,local_label_dist= label_attack(data,attacker,victim,schedule,attack_name,outputroot)
    label_dist = add_to_dictionary(label_dist,local_label_dist)
    

    attack_name = 'TFTP'
    schedule = ('12/01/2018 01:35 PM','12/01/2018 05:15 PM')
    data,local_label_dist = label_attack(data,attacker,victim,schedule,attack_name,outputroot)
    label_dist = add_to_dictionary(label_dist,local_label_dist)
        
    save_dict_to_csv(join(outputroot,'label_dist.csv'),label_dist)
    print("After attack schedules -------------------")
    print(data.Label.value_counts())

    data.to_csv(join(outputroot,'records.csv'),index=False,encoding='utf-8-sig')


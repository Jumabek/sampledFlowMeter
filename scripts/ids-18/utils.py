import os
from os.path import join
import pandas as pd
import ntpath
from collections import defaultdict
from tqdm import tqdm
from glob import glob
import numpy as np

from multiprocessing import Pool

#dataroot = '/media/juma/data/net_intrusion/ids18/'
dataroot = '/data/juma/data/ids18/'
#dataroot = '/media/juma/data/research/intrusion_detection/dataset/CIC-IDS-2018/'

#ddos_dataroot = '/data/juma/data/ddos/'
#ddos_dataroot = '/media/juma/data/net_intrusion/ddos19/'

def get_threshold():
    return 10000

def ensure_dir(path):
    if not os.path.isdir(path):
        try:
            os.makedirs(path)
        except OSError as exc: # Guard against race condition
            if exc.errno != errno.EEXIST:
                raise

def get_immediate_subdirs(a_dir):
    return [name for name in os.listdir(a_dir)
            if os.path.isdir(os.path.join(a_dir, name))]

def get_max_cf(d):
    fpath = join(dataroot,'CSVs/WS',d,'max_cf_count.txt')
    with open(fpath,'r') as f:
        n = f.readline()
    return int(n)


def get_max_wsaf(d):
    fpath = join(dataroot,'CSVs_r_1.0_m_1.0/WS',d,'max_wsaf_count.txt')
    with open(fpath,'r') as f:
        return int(f.readline())


def get_executables_dir():
    return '../../build/install/SampleMeter/bin'

def get_dtype():
    return {'Flow ID':str , 'Dst Port':int , 'Protocol':int,
       'Flow Duration':int , 'Tot Fwd Pkts':int , 'Tot Bwd Pkts': int,
       'TotLen Fwd Pkts':int , 'TotLen Bwd Pkts':int , 'Fwd Pkt Len Max':int,
       'Fwd Pkt Len Min':int , 'Fwd Pkt Len Mean':float , 'Fwd Pkt Len Std':float,
       'Bwd Pkt Len Max':int , 'Bwd Pkt Len Min':int , 'Bwd Pkt Len Mean':float,
       'Bwd Pkt Len Std':float , 'Flow Byts/s':float , 'Flow Pkts/s':float, 'Flow IAT Mean':float,
       'Flow IAT Std':float , 'Flow IAT Max':int , 'Flow IAT Min':int , 'Fwd IAT Tot':int,
       'Fwd IAT Mean':float , 'Fwd IAT Std':float , 'Fwd IAT Max':int , 'Fwd IAT Min':int,
       'Bwd IAT Tot':int , 'Bwd IAT Mean':float , 'Bwd IAT Std':float , 'Bwd IAT Max':int,
       'Bwd IAT Min':int , 'Fwd PSH Flags':int , 'Bwd PSH Flags':int , 'Fwd URG Flags':int,
       'Bwd URG Flags':int , 'Fwd Header Len':int , 'Bwd Header Len':int , 'Fwd Pkts/s':float,
       'Bwd Pkts/s':float , 'Pkt Len Min':int , 'Pkt Len Max':int , 'Pkt Len Mean':float,
       'Pkt Len Std':float , 'Pkt Len Var':float , 'FIN Flag Cnt':int , 'SYN Flag Cnt':int,
       'RST Flag Cnt':int , 'PSH Flag Cnt':int , 'ACK Flag Cnt':int , 'URG Flag Cnt':int,
       'CWE Flag Count':int , 'ECE Flag Cnt':int , 'Down/Up Ratio':float , 'Pkt Size Avg':float,
       'Fwd Seg Size Avg':float , 'Bwd Seg Size Avg':float , 'Fwd Byts/b Avg':float,
       'Fwd Pkts/b Avg':float , 'Fwd Blk Rate Avg':float , 'Bwd Byts/b Avg':float,
       'Bwd Pkts/b Avg':float , 'Bwd Blk Rate Avg':float , 'Subflow Fwd Pkts':float,
       'Subflow Fwd Byts':float , 'Subflow Bwd Pkts':float , 'Subflow Bwd Byts':float,
       'Init Fwd Win Byts':int , 'Init Bwd Win Byts':int , 'Fwd Act Data Pkts':int,
       'Fwd Seg Size Min':int , 'Active Mean':float , 'Active Std':float , 'Active Max':float,
       'Active Min':float , 'Idle Mean':float , 'Idle Std':float , 'Idle Max':float , 'Idle Min':float , 'Label':str}


def write_labeldist(sampling_dir):
    print(ntpath.basename(sampling_dir))
    label_dist = defaultdict(lambda: 0)
    for fn in tqdm(glob(join(sampling_dir,'*Meter.csv'))):
        df = pd.read_csv(fn,usecols=['Label'])
        dist_i = df['Label'].value_counts()
        for key in dist_i.keys():
            label_dist[key]+=dist_i[key]

    with open(join(sampling_dir,'label_dist.csv'),'w') as f:
        for key in sorted(label_dist.keys()):
            f.write('{},{}\n'.format(key,label_dist[key]))


def get_flow_dist_file(fn):
    df = pd.read_csv(fn, usecols=['Flow ID','Label'], dtype={'Flow ID':str,'Label':str})
    flow_counts = df.groupby(['Label'], as_index=False).agg({'Flow ID': 'nunique'})
    return flow_counts


def get_flow_dist(dataroot):
    print("Obtaining flow distribution")
    flow_dist = defaultdict(lambda: 0)
    fns = [fn for fn in glob(join(dataroot,'*Meter.csv'))]
    results = None
    with Pool() as p:
        results = p.map(get_flow_dist_file,fns)

    for flow_counts in results:
        for row in flow_counts.iterrows():
            label = row[1]['Label']
            count = row[1]['Flow ID']
            flow_dist[label]+=count
    return flow_dist


def write_flowdist(dataroot):
    #write
    flow_dist = get_flow_dist(dataroot)
    with open(join(dataroot,'flow_dist.csv'),'w') as f:
        f.write('{},{}\n'.format('Label','Count'))
        for key in sorted(flow_dist.keys()):
            f.write('{},{}\n'.format(key,flow_dist[key]))
 

def calc_n_write_flow_observation(flow_dist,dataroot):
    #####################
    root = '/data/juma/data/ids18'
    gt_df = pd.read_csv(join(root,'CSVs_r_1.0_m_1.0/WS_l/flow_dist.csv'),encoding='utf-8',usecols=['Label','Count'],dtype={'Label':str,'Count':int})
    benign_list = pd.read_csv(join(root,'categories','benign_list.csv'),header=None)[0].values
    short_attack_list = pd.read_csv(join(root,'categories','short_attack_list.csv'),header=None)[0].values
    long_attack_list = pd.read_csv(join(root,'categories','long_attack_list.csv'),header=None)[0].values
    ##########################
    obsr_df = pd.DataFrame(columns=['Label','Count','Observation rate'])
    for label in np.concatenate((benign_list,short_attack_list,long_attack_list), axis=0):
        if label in flow_dist.keys():
            gt_count = gt_df[gt_df['Label']==label]['Count'].values[0]
            count = flow_dist[label]
            rate = round(100*count/gt_count,2)
        else:
            count = 0
            rate = 0
        obsr_df = obsr_df.append({'Label':label,'Count':count,'Observation rate':rate},ignore_index=True)

    # we need to obtain (1) average malicious obsr rate and (2) total obsr rate
    ben_obsr_df = obsr_df[obsr_df['Label']=='Benign']
    #print("ben_obsr_df")
    #print(ben_obsr_df)
    m_obsr_rate = (obsr_df['Observation rate'].sum()-ben_obsr_df['Observation rate'].values[0])/(len(short_attack_list)+len(long_attack_list))
    count_sum = obsr_df['Count'].sum()-ben_obsr_df['Count'].values[0]

    obsr_df = obsr_df.append({'Label':'Macro average Observation Rate','Count':count_sum,'Observation rate':round(m_obsr_rate,2)},ignore_index=True)
    obsr_df.to_csv(join(dataroot,'observation_rate.csv'),index=False,encoding='utf-8-sig')


def write_flow_obsr(dataroot):
    flow_dist = get_flow_dist(dataroot) 
    calc_n_write_flow_observation(flow_dist, dataroot)
 

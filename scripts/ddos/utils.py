import os
from os.path import join
import pandas as pd

ddos_dataroot = '/data/juma/data/ddos/'
#ddos_dataroot = '/media/juma/data/net_intrusion/ddos19/'


def ensure_dir(path):
    if not os.path.isdir(path):
        try:
            os.makedirs(path)
        except OSError as exc: # Guard against race condition
            if exc.errno != errno.EEXIST:
                raise


def get_max_num_concurrent_flows_train():
    fpath = join(ddos_dataroot,'CSVs/WS/PCAP-01-12/max_cf_count.txt')
    with open(fpath,'r') as f:
        n = f.readline()
    margin = 100
    return int(n)+margin # it is important to cast to INTEGER (for `MAGNIFY`ing later)


def get_max_num_concurrent_flows_test():
    #root = '/home/juma/data/net_intrusion/CIC-IDS-2018/CSVs/without_sampling'
    fpath = join(ddos_dataroot,'CSVs/WS/PCAP-03-11/max_cf_count.txt')
    with open(fpath,'r') as f:
        n = f.readline()
    margin = 100
    return int(n)+margin # it is important to cast to INTEGER (for `MAGNIFY`ing later)


def get_ddos_train_baseline_mem():
    fpath = join(ddos_dataroot,'CSVs/WS/PCAP-01-12/max_wsaf_count.txt')
    with open(fpath,'r') as f:
        n = f.readline()
    margin =100
    n = int(n) +margin
    return n # it is important to cast to INTEGER (for `MAGNIFY`ing later)


def get_ddos_test_baseline_mem():
    fpath = join(ddos_dataroot,'CSVs/WS/PCAP-03-11/max_wsaf_count.txt')
    with open(fpath,'r') as f:
        n = f.readline()

    margin =100
    n = int(n)+margin
    return n # it is important to cast to INTEGER (for `MAGNIFY`ing later)


def get_executables_dir():
    return '../../build/install/SampleMeter/bin'


def get_dtype():
    return {'Flow ID':str ,'Src IP':str,'Dst IP':str, 'Src Port':int, 'Dst Port':int , 'Protocol':int,
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


def get_cols4labeling():
    return ['Flow ID','Src IP','Dst IP','Src Port', 'Dst Port','Timestamp','TimestampMCS', 'Protocol',
       'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
       'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Max',
       'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Std',
       'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean',
       'Bwd Pkt Len Std', 'Flow Byts/s', 'Flow Pkts/s', 'Flow IAT Mean',
       'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Tot',
       'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
       'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max',
       'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags',
       'Bwd URG Flags', 'Fwd Header Len', 'Bwd Header Len', 'Fwd Pkts/s',
       'Bwd Pkts/s', 'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean',
       'Pkt Len Std', 'Pkt Len Var', 'FIN Flag Cnt', 'SYN Flag Cnt',
       'RST Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt',
       'CWE Flag Count', 'ECE Flag Cnt', 'Down/Up Ratio', 'Pkt Size Avg',
       'Fwd Seg Size Avg', 'Bwd Seg Size Avg', 'Fwd Byts/b Avg',
       'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg', 'Bwd Byts/b Avg',
       'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg', 'Subflow Fwd Pkts',
       'Subflow Fwd Byts', 'Subflow Bwd Pkts', 'Subflow Bwd Byts',
       'Init Fwd Win Byts', 'Init Bwd Win Byts', 'Fwd Act Data Pkts',
       'Fwd Seg Size Min', 'Active Mean', 'Active Std', 'Active Max',
       'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min']


def read_ddos_data(dataroot,columns=None,debug=False):
    # only read common attack in both days
    filenames = ['LDAP.csv','MSSQL.csv','NetBIOS.csv','SYN.csv','UDP.csv','UDP-Lag.csv','records.csv']
    if debug:
        n = 1000
        df_list = [pd.read_csv(join(dataroot,fn),usecols=get_cols4ml(),dtype=get_dtype(), skiprows=lambda x: x%n!=0) for fn in filenames]
    else:
        if columns !=None:
            df_list = [pd.read_csv(join(dataroot,fn),usecols=columns) for fn in filenames]

        else:
            df_list = [pd.read_csv(join(dataroot,fn),usecols=get_cols4ml(),dtype=get_dtype()) for fn in filenames]
    if len(df_list)<1:
        print('No file at all, returning')
        return
    combined_csv = pd.concat(df_list,sort=False)
    return combined_csv


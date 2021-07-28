import pandas as pd
from utils import read_ddos_data
import numpy as np
from os.path import join

def group_data(df):
    print("Grouping by FlowID and Label")
    grouped = df.groupby(['Flow ID','Label'])
    ID = [ [flowid,label]  for (flowid,label)  in grouped.groups.keys()]
    groupid,count = np.unique(ID,return_counts=True)
    
    Label = [label for flowid,label in ID]
    ID = np.array(ID)
    return ID,Label


if __name__ =='__main__':
    dataroot = '/data/juma/data/ddos/CSVs_r_1.0/SR_10/FFS_(8,16,4)/PCAP-03-11_l'
    df = read_ddos_data(dataroot,columns=['Flow ID','Label'])
    flowids,flowlabels = group_data(df)
    
    unique_labels,label_counts = np.unique(flowlabels,return_counts=True)
    flow_observation_rate = np.ones(len(unique_labels))*100
    pd.DataFrame({'Label':unique_labels,'Count':label_counts,'Observation Rate':flow_observation_rate}).to_csv(join(dataroot,'flow_dist.csv'),index=False,encoding='utf-8-sig')

    

import pandas as pd
from utils import read_ddos_data
import numpy as np
from os.path import join

def group_data(df):
    print("Grouping by FlowID and Label")
    grouped = df.groupby(['Flow ID','Label'])
    ID = [ [flowid,label]  for (flowid,label)  in grouped.groups.keys()]
    Label = [label for flowid,label in ID]
    ID = np.array(ID)
    return ID,Label


if __name__ =='__main__':
    dataroot = '/data/juma/data/ddos/CSVs_r_1.0/SR_10/SEL_(230,1,1)/PCAP-03-11_l'
    df = read_ddos_data(dataroot,columns=['Flow ID','Label'])
    flowids,flowlabels = group_data(df)    
    unique_labels,label_counts = np.unique(flowlabels,return_counts=True)
    
    #read the GT counts
    gt_root = '/data/juma/data/ddos/CSVs/WS/PCAP-03-11_l'
    gt_df = pd.read_csv(join(gt_root,'flow_dist.csv'),usecols=['Label','Count'])

    #calc flow observation using GT count
    flow_observation_rate = []
    for label,count in zip(unique_labels,label_counts):
        gt_count = gt_df[gt_df['Label']==label]['Count'].values[0]
        flow_observation_rate.append(count*100./gt_count)
        print(label,gt_count,count)

    pd.DataFrame({'Label':unique_labels,'Count':label_counts,'Observation Rate':flow_observation_rate}).round(2).to_csv(join(dataroot,'flow_dist.csv'),index=False,encoding='utf-8-sig')

    

import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from tqdm import tqdm
from datetime import datetime
from datetime import timedelta
import argparse
from glob import glob


def convert_to_datetime(arr):
    fmt = '%H:%M'
    offset = timedelta(hours=11,minutes=36)
    arr_str = []
    for t in arr:
        dt = datetime.fromtimestamp(t/1000000.) - offset
        arr_str.append(dt.strftime(fmt))
    return arr_str


def count_cf_each_sec(df,outfilename):
    MCS_IN_SEC=1000000
    num_seconds = (df['Finish'].max() - df['Start'].min())/MCS_IN_SEC    
    start_sec = df['Start'].min()//MCS_IN_SEC
    end_sec = df['Finish'].max()//MCS_IN_SEC

    timestamps = []
    cf_l = []
    for s in tqdm(range(start_sec,end_sec,1)):
        ts = s*MCS_IN_SEC
        cf = df[(df['Start']<ts) & (df['Finish']>ts)].count()['Flow ID']
        timestamps.append(ts)
        cf_l.append(cf)
    pd.DataFrame({'Timestamp':timestamps,'#CF':cf_l}).to_csv(outfilename)


def count_cf_leg(df,outfilename): # per flow finish time (not per second)
    df = df.sort_values(by=['Start','Finish'])
    cf_l = [df[(df['Finish']>=ts) &(df['Start']<ts)].count()['Flow ID'] for ts in tqdm(df['Finish'].values)]
    #sorting in timely manner
    indices = np.argsort(df['Finish'].values)
    cf_l = np.array(cf_l)[indices]
    pd.DataFrame({'Timestamp':df['Finish'].values[indices],'#CF':cf_l}).to_csv(outfilename)


def plot_cf(filename,legend):
    font = {'size'   : 45}
    plt.rc('font', **font)
    plt.rcParams["axes.linewidth"]  = 2.5
    fig, ax = plt.subplots(nrows=1,ncols=1,sharex=False,figsize=(25,12))

    df = pd.read_csv(filename)
    plt.plot(df['Timestamp'].values,df["#CF"],linewidth=3, label=legend)
    x_ticks = np.linspace(df['Timestamp'].min(),df['Timestamp'].max(),6)
    x_ticks_str = convert_to_datetime(x_ticks)
        
    max_cf_count = df['#CF'].max()
    start = df['Timestamp'].min()
    end = df['Timestamp'].max()
    plt.text((start+end)*1./2,max_cf_count,'{:10.0f}'.format(max_cf_count),fontsize=35)
    plt.plot([start,end],[max_cf_count, max_cf_count],color='black',alpha=.5,linewidth=3)

    plt.xticks(x_ticks,x_ticks_str,fontsize=35)
    plt.grid(linewidth=3)
    plt.xlabel('Timestamp')
    plt.ylabel('#CF')
    plt.yscale('log')
    plt.legend()
    plt.savefig(filename.replace('.csv','.png'))


if __name__=='__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--csv',help='csv file of Features',required=True)
    args = parser.parse_args()
    filename = args.csv
    #filename= '/media/juma/data/net_intrusion/CIC-IDS-2018/CSVs/WS/Thursday-15-02-2018/Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv'
    #filename = '/data/juma/data/ids18/WS/Friday-16-02-2018_TrafficForML_CICFlowMeter.csv'
    for filename in glob('/data/juma/data/ids18/CSVs/WS/*Meter.csv'):
        print(filename)
        df = pd.read_csv(filename,usecols=['Flow ID','TimestampMCS','Flow Duration'], dtype={'Flow ID':str,'TimestampMCS':np.int64,'Flow Duration':np.int64})
        df_flows = pd.DataFrame()
        df['Finish']= df['TimestampMCS']+df['Flow Duration']
        df['Start'] = df['TimestampMCS']
        df.drop(columns=['TimestampMCS','Flow Duration'],inplace=True)
        outfile = filename.replace('.csv','_alive_on_sec_CF.csv')
        #count_cf_each_sec(df,outfile)
        plot_cf(outfile,legend = '#alive flows (FLOWTIMEOUT is used for cut)')

        # not taking into account FIN, FLOWTIMEOUT. 
        dfg = df.groupby('Flow ID').agg({'Flow ID':np.max,'Start':np.min,'Finish':np.max})
        goutfile = filename.replace('.csv','_alive_on_sec_GCF.csv')
        #count_cf_each_sec(dfg,goutfile)
        plot_cf(goutfile,legend = '#alive flows')
        print(df.shape,dfg.shape)


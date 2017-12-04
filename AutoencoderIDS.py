# -*- coding: utf-8 -*-
"""
Created on Mon Dec  4 19:26:42 2017

@author: KIM
"""
import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from mpl_toolkits.mplot3d import Axes3D
import seaborn as sns
from sklearn.decomposition import PCA

class AutoencoderIDS :
    def __init__(self) :
        print('autoencoderIDS')
        
    def getDataFrame(self, dir) :
        #sumDF = pd.DataFrame([])
        filelist = os.listdir(dir)
        frames = []
        for filename in filelist :
            print(dir+'/'+str(filename), end=' ')
            df = pd.read_csv(dir+'/'+filename, sep="\t", header = None)
            print(df.size)
            frames.append(df)
        #sumDF = sumDF.append(df, ignore_index=True)
        sumDF = pd.concat(frames, ignore_index=True)
        return sumDF   
    
    def toNumericData(self, df, save=False, plot=False) :
        print('phase 1')
        service = open('./service.txt', 'r')
        serviceData = service.read().split('\n')
        service.close()
        df[1].replace(serviceData, range(len(serviceData)), inplace=True)
        #make flag to categorical data
        print('phase 13')
        flag = open('./flag.txt', 'r')
        flagData = flag.read().split('\n')
        flag.close()
        #replace_arr_13 = np.array(flag_data)
        df[13].replace(flagData, range(len(flagData)), inplace=True)
        #make IDS_detection as binary (0:not triggered 1:triggered)
        print('phase 14')
        replaceArr14 = []
        for i in df[14].unique() :
            if(i == 0 or i == '0') :
                replaceArr14.append(0)
            else :
                replaceArr14.append(1)
        df[14].replace(df[14].unique(), replaceArr14, inplace=True)
        #make malware_detection as number of the same malware observed during the connection
        print('phase 15')
        replaceArr15 = []
        for i in df[15].unique() :
            if(i == 0 or i == '0') :
                replaceArr15.append(0)
            else :
                replaceArr15.append(1)
        df[15].replace(df[15].unique(), replaceArr15, inplace=True)
        #make Ashula_detection as number of the same shellcode or exploit code observed during the connection
        print('phase 16')
        replaceArr16= []
        for i in df[16].unique() :
            if(i == 0 or i == '0') :
                replaceArr16.append(0)
            else :
                replaceArr16.append(1)
        df[16].replace(df[16].unique(), replaceArr16, inplace=True)
        #make protocol to categorical data
        print('phase 23')
        replaceArr23 = df[23].unique()
        df[23].replace(replaceArr23, range(replaceArr23.shape[0]), inplace=True)
        
        if plot :
            columns = ['Duration', 'Service', 'Source bytes', 'Destination bytes', 'Count', 'Same srv rate', \
           'Serror rate', 'Srv serror rate', 'Dst host count', 'Dst host srv count', 'Dst host same src port rate', \
           'Dst host serror rate', 'Dst host srv serror rate', 'Flag', 'IDS detection', 'Malware detection', \
           'Ashula detection', 'Label', 'Source IP Address', 'Source Port Number', 'Destination IP Address', \
           'Destination Port Number', 'Start Time', 'Duration']
            
            v_features = df.loc[:,0:23].columns
    
            idx = 0
            fig = plt.figure(figsize=(12,18*4))
            gs = gridspec.GridSpec(18, 1)
            for i, cn in enumerate(df[v_features]):
                print(i,idx)
                if(i in [14, 15, 16, 17, 18, 20, 22]) :
                    continue
                
                ax = plt.subplot(gs[idx])
                
                sns.distplot(df[cn][df[17] > 0])
                sns.distplot(df[cn][df[17] < 0])
                ax.set_xlabel('')
                ax.set_title('histogram of feature: ' + columns[cn])
                
                # Save just the portion _inside_ the second axis's boundaries
                extent = ax.get_window_extent().transformed(fig.dpi_scale_trans.inverted())
                plt.savefig('distplot_'+columns[cn]+'.png', bbox_inches=extent.expanded(1.1, 1.2))
                
                idx += 1
            plt.savefig('distplot_all.png', dpi=80)
            print('Save the distplot image in \'distplot_all.png\'')
        
        if save :
            df.describe().to_csv('df_describe.csv')
            df.to_csv('df.csv')
            
        return df
    
    def toAutoEncoderData(self, flag, df=None, csvPath=None) :
        if df == None :
            if csvPath == None :
                return
            df = pd.read_csv(csvPath, sep="\t", header = None)

autoencoder = AutoencoderIDS()
df1 = autoencoder.getDataFrame('./Kyoto2016/2014/01')
df2 = autoencoder.getDataFrame('./Kyoto2016/2014/02')
df3 = autoencoder.getDataFrame('./Kyoto2016/2014/03')
df4 = autoencoder.getDataFrame('./Kyoto2016/2014/04')
df5 = autoencoder.getDataFrame('./Kyoto2016/2014/05')
df6 = autoencoder.getDataFrame('./Kyoto2016/2014/06')

frames = [df1, df2, df3, df4, df5, df6]
df = pd.concat(frames, ignore_index=True)
del df1
del df2
del df3
del df4
del df5
del df6
del frames

#df = autoencoder.getDataFrame('./data')
df2 = autoencoder.toNumericData(df, False, True)
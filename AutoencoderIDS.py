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
import seaborn as sns
from sklearn.preprocessing import OneHotEncoder
import math
import h5py

def getNormalDistData(x, mean, std) :
    return 1/math.sqrt(2*math.pi*(std**2))*math.pow(math.e,-(x-mean)**2/(2*std**2))

def getContactPoint(mean1, std1, mean2, std2) :
    if(mean1 > mean2) :
        mean1, mean2 = mean2, mean1
        std1, std2 = std2, std1
    x = mean1
    weights = 1
    
    while(weights != 0.00001) :
        val1 = getNormalDistData(x+weights, mean1, std1)
        val2 = getNormalDistData(x+weights, mean2, std2)

        if(val1 > val2) :
            x += weights
        else :
            weights /= 10
    return x
    
class AutoencoderIDS :
    def __init__(self) :
        print('autoencoderIDS')
        service = open('./service.txt', 'r')
        self.serviceData = service.read().split('\n')
        service.close()
        flag = open('./flag.txt', 'r')
        self.flagData = flag.read().split('\n')
        flag.close()
        
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
        df[1].replace(self.serviceData, range(len(self.serviceData)), inplace=True)
        #make flag to categorical data
        print('phase 13')
        #replace_arr_13 = np.array(flag_data)
        df[13].replace(self.flagData, range(len(self.flagData)), inplace=True)
        #make IDS_detection as binary (0:not triggered 1:triggered)
        print('phase 14')
        replaceArr14 = [1]*df[14].unique().shape[0]
        if(df[14].unique()[0] == '0' or df[14].unique()[0] == 0) :
            replaceArr14[0] = 0
        """
        for i in df[14].unique() :
            if(i == 0 or i == '0') :
                replaceArr14.append(0)
            else :
                replaceArr14.append(1)
        """
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
        replaceArr16 = [1]*df[16].unique().shape[0]
        if(df[16].unique()[0] == '0' or df[16].unique()[0] == 0) :
            replaceArr16[0] = 0
        """
        replaceArr16= []
        for i in df[16].unique() :
            if(i == 0 or i == '0') :
                replaceArr16.append(0)
            else :
                replaceArr16.append(1)
        """
        df[16].replace(df[16].unique(), replaceArr16, inplace=True)
        #make protocol to categorical data
        print('phase 23')
        df[23].replace(['tcp','udp','icmp'], range(0,3), inplace=True)
        #replaceArr23 = df[23].unique()
        #df[23].replace(replaceArr23, range(replaceArr23.shape[0]), inplace=True)
        df.drop([18, 20, 22], axis=1)

        if plot :
            if not os.path.exists('./plot'):
                os.makedirs('./plot')
            columns = ['Duration', 'Service', 'Source bytes', 'Destination bytes', 'Count', 'Same srv rate', \
           'Serror rate', 'Srv serror rate', 'Dst host count', 'Dst host srv count', 'Dst host same src port rate', \
           'Dst host serror rate', 'Dst host srv serror rate', 'Flag', 'IDS detection', 'Malware detection', \
           'Ashula detection', 'Label', 'Source IP Address', 'Source Port Number', 'Destination IP Address', \
           'Destination Port Number', 'Start Time', 'Duration']
            
            v_features = df.loc[:,0:24].columns
    
            idx = 0
            fig = plt.figure(figsize=(12,18*4))
            gs = gridspec.GridSpec(18, 1)
            for i, cn in enumerate(df[v_features]):
                print(i,idx, cn)
                if(i in [14, 15, 16, 17,18,20,22]) :
                    continue
                
                ax = plt.subplot(gs[idx])
                
                sns.distplot(df[cn][df[17] > 0], bins=50)
                sns.distplot(df[cn][df[17] < 0], bins=50)
                ax.set_xlabel('')
                ax.set_title('histogram of feature: ' + columns[cn])
                
                # Save just the portion _inside_ the second axis's boundaries
                extent = ax.get_window_extent().transformed(fig.dpi_scale_trans.inverted())
                plt.savefig('./plot/distplot_'+columns[cn]+'.png', bbox_inches=extent.expanded(1.1, 1.2))
                
                idx += 1
            plt.savefig('./plot/distplot_all.png', dpi=80)
            print('Save the distplot image in \'distplot_all.png\'')
        
        if save :
            df.describe().to_csv('df_describe.csv')
            df.to_csv('df.csv')
            
        return df
    
    def toAutoEncoderData(self, flag, df=None, csvPath=None, makeHDF5=True, makeCSV=True) :
        enc = OneHotEncoder(n_values=[len(self.serviceData),len(self.flagData),3,3])
        if type(df) == type(None) :
            if type(csvPath) == type(None) :
                return
            df = pd.read_csv(csvPath, sep="\t", header = None)
        
        normalStatistics = df[df[17]>0].describe()
        normalStatistics = normalStatistics.values
        normalMeans = normalStatistics[1]
        normalStds = normalStatistics[2]
        
        attackStatistics = df[df[17]<0].describe()
        attackStatistics = attackStatistics.values
        attackMeans = attackStatistics[1]
        attackStds = attackStatistics[2]

        if flag == 1 :
            df = df[df[17] > 0]
    
        print('phase 0') #std 비교
        contactPoint = getContactPoint(normalMeans[0], normalStds[0], attackMeans[0], attackStds[0])
        df[0] = df[0].map(lambda x : 1 if x > contactPoint else 0)
        print('phase 2') #std 비교
        contactPoint = getContactPoint(normalMeans[2], normalStds[2], attackMeans[2], attackStds[2])
        df[2] = df[2].map(lambda x : 1 if x > contactPoint else 0)
        print('phase 3') #std 비교
        contactPoint = getContactPoint(normalMeans[3], normalStds[3], attackMeans[3], attackStds[3])
        df[3] = df[3].map(lambda x : 1 if x > contactPoint else 0)
        print('phase 4')
        contactPoint = getContactPoint(normalMeans[4], normalStds[4], attackMeans[4], attackStds[4])
        df[4] = df[4].map(lambda x : 1 if x > contactPoint else 0)
        print('phase 8')
        df[8] = df[8]/100
        print('phase 9')
        df[9] = df[9]/100
        
        print('phase 17')
        df[17] = df[17].map(lambda x : 1 if x > 0 else 0)
        label = df[17].values.astype(np.int)  
        #make port_number as one-hot encoding
        #drop 18,20,22
        print('phase 19') #port number reserved port, well-know port, unknown port => one hot encoding
        df[19] = df[19].map(lambda x : 2 if x > 49152 else 1 if x > 1024 else 0)
        
        enc.fit(df[[1,13,19,23]].values)
        
        one_hot_encoding = enc.transform(df[[1,13,19,23]].values).toarray()
        #one_hot_encoding = enc.transform(df[[1,13,23]].values).toarray()
        
        df = df.drop([1,13,17,18,19,20,21,22,23], axis = 1)
        
        inputData = np.concatenate((df, one_hot_encoding), axis = 1).astype(np.float32)
        
        print(inputData.shape)
        if(makeCSV == True) :
            if not os.path.exists('./csv'):
                os.makedirs('./csv')
            if(flag == 1) :
                inputName = 'training_input.csv'
                labelName = 'training_label.csv'
            else :
                inputName = 'test_input.csv'
                labelName = 'test_label.csv'
            pd.DataFrame(inputData).to_csv('./csv/'+inputName)
            pd.DataFrame(label).to_csv('./csv/'+labelName)
        
        if(makeHDF5 == True) :
            if not os.path.exists('./hdf5'):
                os.makedirs('./hdf5')
            
            if(flag == 1) :
                filelist = open('./train.filelist.txt', 'w')
                filename = 'training_'
            else :
                filelist = open('./test.filelist.txt', 'w')
                filename = 'test_'
            length = math.ceil(inputData.shape[0]/100000)
            
            for idx in range(length) :
                hdf5FilePath = './hdf5/'+filename+str(idx)+'.hdf5'
                print(hdf5FilePath)

                if(idx+1 == length) :
                    with h5py.File(hdf5FilePath, 'w') as f:
                        f['data'] = inputData[idx*100000:]
                        f['label'] = label[idx*100000:]
                    filelist.write(hdf5FilePath)
                else :
                    with h5py.File(hdf5FilePath, 'w') as f:
                        #f['data'] = inputData[idx*100000:(idx+1)*100000]
                        #f['label'] = label[idx*100000:(idx+1)*100000]
                        f['data'] = inputData
                        f['label'] = label
                    filelist.write(hdf5FilePath+'\n')
            filelist.close()

autoencoder = AutoencoderIDS()
df = autoencoder.getDataFrame('./data')
df2 = autoencoder.toNumericData(df, False, False)
a = autoencoder.toAutoEncoderData(1, df2, makeHDF5 = False,makeCSV =  True)
a = autoencoder.toAutoEncoderData(0, df2, makeHDF5 = False,makeCSV =  True)
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
from sklearn.preprocessing import OneHotEncoder, MinMaxScaler
from sklearn import metrics
from sklearn.model_selection import KFold
import math
import h5py
#import caffe

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
        filelist = os.listdir(dir)
        frames = []
        for filename in filelist :
            print(dir+'/'+str(filename), end=' ')
            df = pd.read_csv(dir+'/'+filename, sep="\t", header = None)
            print(df.size)
            frames.append(df)
        sumDF = pd.concat(frames, ignore_index=True)
        
        return sumDF   
    
    def toNumericData(self, df, save=False, makePlot=False) :
        print('Data size')
        print(df.shape)
        
        print('filtering')
        df = df[(df[17] < 0) | ((df[17]>0) & (df[14] == '0') & (df[15] == '0') & (df[16] == '0'))]
        print(df.shape)        

        print('phase 1')
        df[1].replace(self.serviceData, range(len(self.serviceData)), inplace=True)
        #make flag to categorical data
        print('phase 13')
        df[13].replace(self.flagData, range(len(self.flagData)), inplace=True)
        #make protocol to categorical data
        print('phase 23')
        df[23].replace(['tcp','udp','icmp'], range(0,3), inplace=True)

        #replaceArr23 = df[23].unique()
        #df[23].replace(replaceArr23, range(replaceArr23.shape[0]), inplace=True)
        df.drop([14,15,16,18, 20, 22], axis=1, inplace=True)

        if makePlot :
            if not os.path.exists('./plot'):
                os.makedirs('./plot')
            columns = ['Duration', 'Service', 'Source bytes', 'Destination bytes', 'Count', 'Same srv rate', \
           'Serror rate', 'Srv serror rate', 'Dst host count', 'Dst host srv count', 'Dst host same src port rate', \
           'Dst host serror rate', 'Dst host srv serror rate', 'Flag', 'IDS detection', 'Malware detection', \
           'Ashula detection', 'Label', 'Source IP Address', 'Source Port Number', 'Destination IP Address', \
           'Destination Port Number', 'Start Time', 'Duration']
            
            v_features = df.loc[:,0:24].columns
    
            idx = 0
            fig = plt.figure(figsize=(12,17*4))
            gs = gridspec.GridSpec(17, 1)
            for i, cn in enumerate(df[v_features]):
                print(i,idx, cn)
                if(cn in [14,15,16,17,18,20,22]) :
                    continue
                
                ax = plt.subplot(gs[idx])
                try :
                    sns.kdeplot(df[cn][df[17] > 0], lw=3, label="normal")
                except :
                    sns.kdeplot(pd.concat((df[cn][df[17] > 0],pd.DataFrame([1])))[0], lw=3, label="normal")
                try :
                    sns.kdeplot(df[cn][df[17] < 0], lw=3, label="abnormal")   
                except :
                    sns.kdeplot(pd.concat((df[cn][df[17] < 0],pd.DataFrame([1])))[0], lw=3, label="abnormal")
                ax.set_xlabel('')
                ax.set_title('histogram of feature: ' + columns[cn])
                
                # Save just the portion _inside_ the second axis's boundaries
                extent = ax.get_window_extent().transformed(fig.dpi_scale_trans.inverted())
                plt.savefig('./plot/distplot_'+columns[cn]+'.png', bbox_inches=extent.expanded(1.1, 1.2))
                
                idx += 1
            plt.savefig('./plot/distplot_all.png', dpi=80)
            print('Save the distplot image in \'distplot_all.png\'')
        
        if save :
            if not os.path.exists('./csv'):
                os.makedirs('./csv')
            if not os.path.exists('./describe'):
                os.makedirs('./describe')
            df.describe().to_csv('./describe/'+save+'_describe.csv')
            df.to_csv('./csv/'+save+'.csv', sep="\t", header = None, index=False)
            
        return df
    
    def toAutoEncoderData(self, flag, csvPath) :
        scaler = MinMaxScaler()
        enc = OneHotEncoder(n_values=[len(self.serviceData),len(self.flagData),3,3,3]) #85+13+3+3+3 = 107
        
        if os.path.isfile(csvPath) :
            df = pd.read_csv(csvPath, sep="\t", header = None)
        else :
            df = self.getDataFrame(csvPath)
        
        numericDataDesc = df.loc[:, [0,2,3]].describe()
        #df[df[14]>0].describe(include='all').to_csv('normal_log_desc.csv')
        #df[df[14]<0].describe(include='all').to_csv('attack_log_desc.csv')
    
        print('phase 0')
        iqr = (numericDataDesc[0].values[6]-numericDataDesc[0].values[4])*1.5
        standard = numericDataDesc[0].values[5]+iqr
        df[0] = df[0].map(lambda x : standard if x > standard else x)
        print('phase 2')
        iqr = (numericDataDesc[2].values[6]-numericDataDesc[2].values[4])*1.5
        standard = numericDataDesc[2].values[5]+iqr
        if standard == 0 :
            df[2] = df[2].map(lambda x : 1 if x > 0 else 0)
        else :
            df[2] = df[2].map(lambda x : standard if x > standard else x)
        print('phase 3')
        iqr = (numericDataDesc[3].values[6]-numericDataDesc[3].values[4])*1.5
        standard = numericDataDesc[3].values[5]+iqr
        if standard == 0 :
            df[3] = df[3].map(lambda x : 1 if x > 0 else 0)
        else :
            df[3] = df[3].map(lambda x : standard if x > standard else x)
        print('phase 4')
        df[4] = df[4]/100
        print('phase 8')
        df[8] = df[8]/100
        print('phase 9')
        df[9] = df[9]/100        
        print('phase 17')
        df[14] = df[14].map(lambda x : 1 if x > 0 else 0)
        label = df[14].values.astype(np.int)
        label = label.reshape((label.shape[0],1))
        #make port_number as one-hot encoding
        print('phase 19') #port number reserved port, well-know port, unknown port => one hot encoding
        df[15] = df[15].map(lambda x : 2 if x > 49152 else 1 if x > 1024 else 0)
        print('phase 21') #port number reserved port, well-know port, unknown port => one hot encoding
        df[16] = df[16].map(lambda x : 2 if x > 49152 else 1 if x > 1024 else 0)

        scaler.fit(df[[0,2,3]].values)
        df[[0,2,3]] = scaler.transform(df[[0,2,3]].values)
        
        enc.fit(df[[1,13,15,16,17]].values)
        oneHotEncoding = enc.transform(df[[1,13,15,16,17]].values).toarray()
        

        #already droped 18,20,22
        #2,3,4,5,6,7,8,9,10,11,12 => 11
        if(flag == 1) :
            #Training set은 99:1 3개 100:0 1개
            attackLogIdx = df[df[14]==0].sample(n=df[df[14]==1].shape[0]).index
            normalLogIdx = df[df[14]==1].index
            df.drop([1,13,14,15,16,17], axis = 1, inplace=True)

            attackLogList = np.concatenate((df.loc[attackLogIdx], oneHotEncoding[attackLogIdx]),axis=1)
            attackDF = pd.DataFrame(attackLogList)
            del attackLogList

            normalLogList = np.concatenate((df.loc[normalLogIdx], oneHotEncoding[normalLogIdx]),axis=1)
            normalDF = pd.DataFrame(normalLogList)
            del normalLogList
            
            attackDF.drop_duplicates(inplace=True)
            normalDF.drop_duplicates(inplace=True)

            attackDF = attackDF.sample(n=int(normalDF.shape[0]*1/33)//3*3)
           
            attackLogList = attackDF.values
            normalLogList = normalDF.values
            del attackDF
            del normalDF
            
            kf = KFold(n_splits=3)
            kf.get_n_splits(attackLogList)
            
            attackDataIdx = []
            for trainIdx, testIdx in kf.split(attackLogList) :
                attackDataIdx.append(testIdx)
            
            if not os.path.exists('./hdf5'):
                os.makedirs('./hdf5')

            idx = 0
            for idxList in attackDataIdx :
                attackData = attackLogList[idxList]
                print('attack :', attackData.shape)
                print('normal :', normalLogList.shape)
                inputData = np.concatenate((normalLogList, attackData), axis=0).astype(np.float32)
                label = np.array([1]*normalLogList.shape[0]+[0]*attackData.shape[0]).reshape((normalLogList.shape[0]+attackData.shape[0],1))
                filename = 'mixed_trainingset_'+str(idx)
                
                print(filename+'_data.csv')
                print(filename+'_label.csv')
                pd.DataFrame(inputData).to_csv(filename+'_data.csv', header=False, index=False)
                pd.DataFrame(label).to_csv(filename+'_label.csv', header=False, index=False)
                
                length = math.ceil(inputData.shape[0]/100000)

                print('mixed_trainingset : ', inputData.shape, label.shape)                
                for fileIdx in range(length) :
                    hdf5FilePath = './hdf5/'+filename+'_'+str(fileIdx)+'.hdf5'
                    print(hdf5FilePath)
    
                    if(idx+1 == length) :
                        with h5py.File(hdf5FilePath, 'w') as f:
                            f['data'] = inputData[idx*100000:]
                            f['label'] = label[idx*100000:]
                    else :
                        with h5py.File(hdf5FilePath, 'w') as f:
                            f['data'] = inputData[idx*100000:(idx+1)*100000]
                            f['label'] = label[idx*100000:(idx+1)*100000]
                idx+=1
            
            #순수 trainingset
            inputData = normalLogList.astype(np.float32)
            label = np.array([1]*inputData.shape[0]).reshape((inputData.shape[0],1))
            filename = 'pure_trainingset'
            
            print(filename+'_data.csv')
            print(filename+'_label.csv')
            pd.DataFrame(inputData).to_csv(filename+'_data.csv', header=False, index=False)
            pd.DataFrame(label).to_csv(filename+'_label.csv', header=False, index=False)
            
            length = math.ceil(inputData.shape[0]/100000)
            
            print('pure_trainingset : ', inputData.shape, label.shape)
                
            for idx in range(length) :
                hdf5FilePath = './hdf5/'+filename+'_'+str(idx)+'.hdf5'
                print(hdf5FilePath)

                if(idx+1 == length) :
                    with h5py.File(hdf5FilePath, 'w') as f:
                        f['data'] = inputData[idx*100000:]
                        f['label'] = label[idx*100000:]
                else :
                    with h5py.File(hdf5FilePath, 'w') as f:
                        f['data'] = inputData[idx*100000:(idx+1)*100000]
                        f['label'] = label[idx*100000:(idx+1)*100000]
            
        else :
            #Test set은 50:50 1개
            attackLogIdx = df[df[14]==0].sample(n=df[df[14]==1].shape[0]*2).index
            normalLogIdx = df[df[14]==1].index
            df.drop([1,13,14,15,16,17], axis = 1, inplace=True)
            attackLogList = np.concatenate((df.loc[attackLogIdx], oneHotEncoding[attackLogIdx]),axis=1)
            attackDF = pd.DataFrame(attackLogList)
            del attackLogList
            
            normalLogList = np.concatenate((df.loc[normalLogIdx], oneHotEncoding[normalLogIdx]),axis=1)
            normalDF = pd.DataFrame(normalLogList)
            del normalLogList
            
            attackDF.drop_duplicates(inplace=True)
            normalDF.drop_duplicates(inplace=True)
            attackDF = attackDF.sample(n=int(normalDF.shape[0]))
           
            attackLogList = attackDF.values
            normalLogList = normalDF.values
            del attackDF
            del normalDF
                        
            if not os.path.exists('./hdf5'):
                os.makedirs('./hdf5')
            
            print(attackLogList.shape, normalLogList.shape)
            #testset
            inputData = np.concatenate((normalLogList, attackLogList), axis=0).astype(np.float32)
            label = np.array([1]*normalLogList.shape[0]+[0]*attackLogList.shape[0]).reshape((inputData.shape[0],1))
            filename = 'testset'
            
            print(filename+'_data.csv')
            print(filename+'_label.csv')
            pd.DataFrame(inputData).to_csv(filename+'_data.csv', header=False, index=False)
            pd.DataFrame(label).to_csv(filename+'_label.csv', header=False, index=False)

            length = math.ceil(inputData.shape[0]/100000)
            
            print('testset : ', inputData.shape, label.shape)
                
            for idx in range(length) :
                hdf5FilePath = './hdf5/'+filename+'_'+str(idx)+'.hdf5'
                print(hdf5FilePath)

                if(idx+1 == length) :
                    with h5py.File(hdf5FilePath, 'w') as f:
                        f['data'] = inputData[idx*100000:]
                        f['label'] = label[idx*100000:]
                else :
                    with h5py.File(hdf5FilePath, 'w') as f:
                        f['data'] = inputData[idx*100000:(idx+1)*100000]
                        f['label'] = label[idx*100000:(idx+1)*100000]
            
    def deploy(self, model, weights, df=None, label=None, hdf5Path=None, makeCSV=True, makePlot=True) :
        def cross_entropy(y, p) :    
            result = 0
            for idx in range(y.shape[0]) :
                if(y[idx] == 1) :
                    b = -math.log10(p[idx])
                    result += b
                else :
                    b = -(y[idx]*math.log10(p[idx]) + (1-y[idx])*math.log10(1-p[idx]))
                    result += b
            return result
        if type(df) == type(None) :
            if type(hdf5Path) == type(None) :
                return
            with h5py.File(hdf5Path, 'r') as f:
                data = f['.']['data'].value
                labels = f['.']['label'].value
        else :
            data = df.values
            labels = label.values
        
        print(data.shape)
        
        net = caffe.Net(model, weights, caffe.TEST)
        normalDataLoss = []
        attackDataLoss = []
        
        for idx in range(data.shape[0]) :
            if idx%100000 == 0 :
                print(idx)
            net.blobs['data'].data[...] = data[idx]
            
            res = net.forward()
            loss = cross_entropy(data[idx], res['decode1neuron'].reshape((res['decode1neuron'].shape[1])))
            if(labels[idx] == 1) :
                normalDataLoss.append(loss)
            else:
                attackDataLoss.append(loss)
                
        print("Normal data loss("+len(normalDataLoss)+") : ", np.average(np.array(normalDataLoss)))
        print("Attack data loss("+len(attackDataLoss)+") : ", np.average(np.array(attackDataLoss)))
    
        allDataLoss = normalDataLoss+attackDataLoss
        print("Sum : ",len(allDataLoss))
        allLabel = [1]*len(normalDataLoss)+[0]*len(attackDataLoss)
        fpr, tpr, thresholds = metrics.roc_curve(np.array(allLabel), np.array(allDataLoss), pos_label=0, drop_intermediate=False)
        
        if makePlot : 
            if not os.path.exists('./plot'):
                os.makedirs('./plot')
            plt.figure()
            lw = 2
            plt.plot(fpr, tpr, color='darkorange', lw=lw, )
            plt.plot([0, 1], [0, 1], color='navy', lw=lw, linestyle='--')
            plt.xlim([0.0, 1.0])
            plt.ylim([0.0, 1.05])
            plt.xlabel('False Positive Rate')
            plt.ylabel('True Positive Rate')
            plt.title('DDOS detection AutoEncoder ROC-curve')
            plt.legend(loc="lower right")
            plt.savefig('./plot/deploy_roc_curve.png', dpi=80)
            plt.show()
        
        if makeCSV :
            if not os.path.exists('./csv'):
                os.makedirs('./csv')
            
            threshold = []
            recall = []
            precision = []
            specificity = []
            f1_measure = []
            for rate in range(10, 20, 1) :
                truePositiveRate = tpr[np.where(tpr>(rate*0.05))[0][0]]
                falsePositiveRate = fpr[np.where(tpr>(rate*0.05))[0][0]]
                recall.append(truePositiveRate)
                precision.append(truePositiveRate*len(attackDataLoss))/(truePositiveRate*len(attackDataLoss)+falsePositiveRate*len(normalDataLoss))
                specificity.append(1-falsePositiveRate)
                f1_measure.append((2*recall*precision)/(precision+recall))
                threshold.append(thresholds[np.where(tpr>(rate*0.05))[0][0]])
            frames = pd.DataFrame({'true positive rate' : truePositiveRate,
                          'false positive rate' : falsePositiveRate,
                          'recall' : recall,
                          'precision' : precision,
                          'specificity' : specificity,
                          'f1-measure' : f1_measure,
                          'threshold' : threshold})
            frames.to_csv('./csv/deploy_description.csv', sep="\t", index=False)

# -*- coding: utf-8 -*-
"""
Created on Wed Dec  6 16:18:50 2017

@author: KIM
"""
import AutoencoderIDS
import os
import pandas as pd

dirArr = ['01','02','03','04','05','06','07','08','09','10','11','12']
#dirArr = ['03','04','05','06','07','08','09','10','11','12']

#dirArr = ['10','11','12']

autoencoder = AutoencoderIDS.AutoencoderIDS()
df = autoencoder.getDataFrame('./data')
autoencoder.toNumericData(df, save='./', makePlot=False)
autoencoder.toAutoEncoderData(0,csvPath='./csv/')
autoencoder.toAutoEncoderData(1,csvPath='./csv/')
"""
frames = []
for dir in dirArr :
    df = autoencoder.getDataFrame('./Kyoto2016/2014/'+dir)
    frames.append(df)
sum_df = pd.concat(frames)
del frames
autoencoder.toNumericData(sum_df, save='2014'+dir, makePlot=True)

frames = []
for dir in dirArr :
    df = autoencoder.getDataFrame('./Kyoto2016/2015/'+dir)
    frames.append(df)
sum_df = pd.concat(frames)
del frames
autoencoder.toNumericData(sum_df, save='2015'+dir, makePlot=False)
"""
"""
dirlist = os.listdir('./csv')

for filename in dirlist :
    autoencoder.toAutoEncoderData(1, df=None, csvPath='./csv/'+filename,
                                 dropDuplicate=True, makeHDF5=True, makeCSV=False)
"""
#autoencoder.toAutoEncoderData(1, df=None, csvPath='./csv',
#                                 dropDuplicate=True, makeHDF5=True, makeCSV=False)

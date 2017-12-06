# -*- coding: utf-8 -*-
"""
Created on Wed Dec  6 16:18:50 2017

@author: KIM
"""
import AutoencoderIDS


dirArr = ['01','02','03','04','05','06','07''08','09','10','11','12']

autoencoder = AutoencoderIDS.AutoencoderIDS()
for dir in dirArr :
    df = autoencoder.getDataFrame('./Kyoto2016/2014/'+dir)
    autoencoder.toNumericData(df, save='2014'+dir, makePlot=False)
del df
autoencoder.toAutoEncoderData(1, df=None, csvPath='./csv',
                                 dropDuplicate=True, makeHDF5=True, makeCSV=False)
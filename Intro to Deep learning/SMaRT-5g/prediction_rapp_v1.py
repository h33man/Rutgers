#!/usr/bin/env python3
#SPDX-License-Identifier: Apache-2.0
#Copyright 2024 Intel Corporation

from flask import Flask,request
import pandas as pd
import tensorflow as tf
import numpy as np
import json
from tensorflow import keras
from keras.models import Sequential
from keras import layers
from keras.callbacks import ModelCheckpoint, EarlyStopping

model = None

def convert2matrix(data_arr, look_back, full_data):
  X, Y =[], []
  for i in range(len(data_arr)-look_back):
    d=i+look_back
    xdata = data_arr[i:d]
    X.append(xdata)
    Y.append(data_arr[d])
return np.array(X), np.array(Y)

def model_dnn(look_back):
   model = Sequential()
   model.add(Input(shape=(look_back), batch_size=10, dtype=tf.float32))
   model.add(layers.Embedding(input_dim=300, output_dim=64))
   model.add(LSTM(32))
   #model.add(LSTM(32, return_sequences=True))  # Bidirectional LSTM
   #model.add(LSTM(16))  # Additional LSTM layer   
   model.add(Dense(look_back, activation='relu'))
   model.add(Dense(1))
   model.compile(loss= "mse",  optimizer='adam', metrics = ['mse', 'mae'])

   return model

df = pd.DataFrame(pd.read_csv("load_test.csv"))

train_size = 300
val_size = 84
train, val, test = (df['Load'].tolist())[0:train_size], (df['Load'].tolist())[train_size:train_size+val_size], (df['Load'].tolist())[train_size+val_size:len(df.values)]
look_back = 8

print("--------------------------------------------")
trainX, trainY = convert2matrix(train, look_back, df[0:train_size])
valX, valY = convert2matrix(val, look_back, df[train_size:train_size+val_size])
testX, testY = convert2matrix(test, look_back, df[train_size+val_size:])
model = model_dnn(look_back)
model.fit(trainX,trainY, epochs=1000, batch_size=10, verbose=2, validation_data=(valX,valY),
         callbacks=[EarlyStopping(monitor='val_loss', patience=100)],shuffle=False)

print("Evaluate on test data")
# Reshape testX to have 3D shape (num_samples, look_back, 1)
tX = np.reshape(testX, (testX.shape[0], look_back, 1))
Z = model.predict(tX)
# Print predictions and actual values
for i in range(len(testY)):
   print(f"Predicted: {Z[i][0]:.6f}, \tActual: {testY[i]}, \t% Error: {abs(Z[i][0]-testY[i])/testY[i]:.2f}")

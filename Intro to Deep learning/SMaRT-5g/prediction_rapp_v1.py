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
from keras.layers import Input, LSTM, Bidirectional, Dense, Embedding
from keras import layers
from keras.callbacks import ModelCheckpoint, EarlyStopping
import matplotlib.pyplot as plt

app = Flask(__name__)

model = None


#@app.route("/predict", methods=['POST'])
def predict():
    
    l = []
    req = json.loads(request.json)
    print(req)
    le = len(req)
    l.append(req[le - 8:])
    Z = model.predict(np.array(l))
    print(str(Z[0][0]))
    return ([str(int(Z[0][0]))])

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
#    model.add(Dense(units=32, input_dim=look_back, activation='relu'))
    """
    source = Input(shape=(look_back,), batch_size=10, dtype=tf.int32, name='Input')
    embedding = Embedding(input_dim=400, output_dim=196, name='Embedding')(source)
    lstm = LSTM(32, name = 'LSTM')(embedding)
    predicted_var = Dense(1, activation='sigmoid', name='Output')(lstm)
    model = tf.keras.Model(inputs=[source], outputs=[predicted_var])
    model.compile(
      optimizer='adam',
      loss='binary_crossentropy',
      metrics=['acc'])
    """
    model.add(Input(shape=(look_back), batch_size=10, dtype=tf.int32))
    model.add(layers.Embedding(input_dim=400, output_dim=64))

# Add a LSTM layer with 128 internal units.
 #   model.add(layers.LSTM(128))

# Add a Dense layer with 10 units.
 #   model.add(layers.Dense(1))

#    model.add(Embedding(input_dim=look_back, output_dim=32))
    model.add(LSTM(32))
    model.add(Dense(look_back, activation='relu'))
    model.add(Dense(1))

    model.compile(loss= "mse",  optimizer='adam', metrics = ['mse', 'mae', 'accuracy'])
    return model


df = pd.DataFrame(pd.read_csv("load_test.csv"))
train_size = 300
train, test = (df['Load'].tolist())[0:train_size], (df['Load'].tolist())[train_size:len(df.values)]
look_back = 8
print("--------------------------------------------")
trainX, trainY = convert2matrix(train, look_back, df[0:train_size])
testX, testY = convert2matrix(test, look_back, df[train_size:])
model = model_dnn(look_back)
#print(trainX, trainY)
#print(model)
model.fit(trainX,trainY, epochs=1000, batch_size=10, verbose=2, validation_data=(testX,testY),
          callbacks=[EarlyStopping(monitor='val_loss', patience=100)],shuffle=False)
#accuracy = model.history.history['Accuracy']
#val_accuracy = model.history.history["val_accuracy"]
#print("accuracy:", accuracy)
#print("val_accuracy:", val_accuracy)
"""
plt.plot(accuracy, label="accuracy")
plt.plot(val_accuracy, label="validation accuracy")
plt.ylabel("Accuracy")
plt.xlabel("Epoch")
plt.legend()
plt.show()

l=[[10,20,30,40,50,60,70,80]]
"""
#l=[[29.30334455581717,
l=[[44.23607735762719,
58.848893061607804,
32.072068234682476,
39.80715407376135,
41.77487901209854,
37.10841876361252,
44.70133458145449,
34.35087410242001]]
#28.334731239338517

Z = model.predict(np.array(l))
print(str(Z[0][0]))


#app.run(host='0.0.0.0', port=9008)

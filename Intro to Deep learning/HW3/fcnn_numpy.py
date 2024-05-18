#HW3 b) Numpy only, FC layer-based neural network to recongnize hand-written digits
from __future__ import print_function
import math
import numpy as np  
from download_mnist import load
import operator  
import time
import collections
import matplotlib.pyplot as plt
from past.builtins import xrange

x_train, y_train, x_test, y_test = load()
x_val=x_train[50000:]
y_val=y_train[50000:]
x_train=x_train[:50000]
y_train=y_train[:50000]

N,D,H1,H2,K = 64,784,500,200,10
w1 = 0.005 * np.random.randn(D, H1)
b1 = np.zeros((1,H1))
w2 = 0.005 * np.random.randn(H1, H2)
b2 = np.zeros((1,H2))
w3 = 0.005 * np.random.randn(H2, K)
b3 = np.zeros((1,K))

lr=1e-3
reg=1e-1
epochs = 10

def predict(x):
  #compute scores
  h1 = np.maximum(0,np.dot(x, w1) + b1)
  h2 = np.maximum(0,np.dot(h1, w2) + b2)
  scores = np.dot(h2, w3) + b3
  y_pred = np.argmax(scores, axis=1)
  return y_pred

if __name__ == '__main__':
  start_time = time.time()
  iters = int(x_train.shape[0]/N)
  for epoch in xrange(epochs) :
   for i in xrange(iters):

    x=x_train[i*N:i*N+N]
    y=y_train[i*N:i*N+N]

#    indices = np.random.choice(x_train.shape[0], N, replace=False)
#    x = x_train[indices]
#    y = y_train[indices]
            
    #forward pass
    h1=np.maximum(0,np.dot(x, w1) + b1)
    h2=np.maximum(0,np.dot(h1, w2) + b2)
    scores=np.dot(h2, w3) + b3

    #Compute loss
    exp_scores = np.exp(scores)
    probs = exp_scores / np.sum(exp_scores, axis=1, keepdims=True)
    correct_logprobs = -np.log(probs[range(N),y])
    data_loss = np.sum(correct_logprobs)/N
    reg_loss = 0.5 * reg * (np.sum(w3*w3) + np.sum(w2*w2) + np.sum(w1*w1))
    loss = data_loss + reg_loss

    #Backward pass: compute gradients
    dscores = probs
    dscores[range(N),y] -= 1
    dscores /= N

    dw3 = np.dot(h2.T, dscores)
    db3 = np.sum(dscores, axis=0, keepdims=True)
    dh2 = np.dot(dscores, w3.T)
    dh2[h2 <= 0] = 0

    dw2 = np.dot(h1.T, dh2)
    db2 = np.sum(dh2, axis=0, keepdims=True)
    dh1 = np.dot(dh2, w2.T)
    dh1[h1 <= 0] = 0

    dw1 = np.dot(x.T, dh1)
    db1 = np.sum(dh1, axis=0, keepdims=True)

    #Update weights
    w1 += -lr * (dw1 + reg * w1)
    w2 += -lr * (dw2 + reg * w2)
    w3 += -lr * (dw3 + reg * w3)
    b1 += -lr * db1 * lr
    b2 += -lr * db2
    b3 += -lr * db3

    if i % 100 == 0:
      print('Epoch %d iteration %d / %d: loss %f val_acc %f train_acc %f' % (epoch+1, i, 
            iters, loss, (predict(x_val) == y_val).mean(), 
                    (predict(x) == y).mean()))

  val_acc = (predict(x_val) == y_val).mean()
  train_acc = (predict(x_train) == y_train).mean()
  print('Validation accuracy: ', val_acc)
  print('Train accuracy: ', train_acc)
  print ("---execution time: %s seconds ---" % (time.time() - start_time))
  test_acc = (predict(x_test) == y_test).mean()
  print('Test accuracy: ', test_acc)
  
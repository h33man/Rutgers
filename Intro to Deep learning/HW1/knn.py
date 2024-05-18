import math
import numpy as np  
from download_mnist import load
import operator  
import time
import collections

# classify using kNN  
#x_train = np.load('../x_train.npy')
#y_train = np.load('../y_train.npy')
#x_test = np.load('../x_test.npy')
#y_test = np.load('../y_test.npy')
x_train, y_train, x_test, y_test = load()
x_train = x_train.reshape(60000,28,28)
x_test  = x_test.reshape(10000,28,28)
x_train = x_train.astype(float)
x_test = x_test.astype(float)

def kNNClassify(newInput, dataSet, labels, k): 
    result=[]
    ########################
    # Input your code here #
    ########################
    n=newInput.shape[0]
    result=np.zeros(n, dtype=labels.dtype)
    for i in range(n):
      #Compute L2 distances
      d=np.sum((np.abs(dataSet-newInput[i]))**2,axis=(1,2)) ** 1/2
      #Select k closest neighbors
      neigh=np.argsort(d)[:k]
      #Find the most common label
      m=collections.Counter(neigh).most_common()[0][0]    

      result[i]=labels[m]
  
    ####################
    # End of your code #
    ####################
    return result

start_time = time.time()
outputlabels=kNNClassify(x_test[0:20],x_train,y_train,4)
result = y_test[0:20] - outputlabels
result = (1 - np.count_nonzero(result)/len(outputlabels))
print ("---classification accuracy for knn on mnist: %s ---" %result)
print ("---execution time: %s seconds ---" % (time.time() - start_time))

""" Output 
Downloading train-images-idx3-ubyte.gz...
Downloading t10k-images-idx3-ubyte.gz...
Downloading train-labels-idx1-ubyte.gz...
Downloading t10k-labels-idx1-ubyte.gz...
Download complete.
Save complete.

!python knn.py
---classification accuracy for knn on mnist: 1.0 ---
---execution time: 7.56325364112854 seconds ---
"""

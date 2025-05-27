#importing basic packages
import pandas as pd
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt


#Loading the data
data0 = pd.read_csv('5.urldata.csv')
data0.head()

#Checking the shape of the dataset
data0.shape

#Listing the features of the dataset
data0.columns

#Information about the dataset
data0.info()

#Plotting the data distribution
data0.hist(bins = 50,figsize = (15,15))
plt.show()

#Correlation heatmap

plt.figure(figsize=(15,13))
sns.heatmap(data0.corr())
plt.show()
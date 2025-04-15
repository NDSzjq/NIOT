import numpy as np
import random

bucket_num = 32
data_num = 30000


# Read data file
data = np.loadtxt("UCI_Credit_Card.csv", delimiter=",")[:data_num].T




f = open('app/credit_bucket_data_test', 'w+')




for i in range(data.shape[0]-1):
	print(i)
	maximum = np.max(data[i])
	minimum = np.min(data[i])
	threshold = np.array([(maximum-minimum)/bucket_num*(j)+minimum for j in range(bucket_num+1)])
	threshold[0] = -1000000000
	threshold[bucket_num] = 1000000000



	for j in range(bucket_num):
		strA = ''
		strB = ''
		strO = ''
		for n in range(data.shape[1]):
			if ((data[i][n] <= threshold[j+1]) and (data[i][n] > threshold[j])):
				strA += '0'
				strB += '0'
				strO += '1'
			else:
				rb = random.randint(0,1)
				strA += str(rb)
				strB += str(rb^1)
				strO += '0'
		# f.write(strO+'\n')
		# print(strO)

		f.write(strA+'\n')
		f.write(strB+'\n')
f.write('labels'+'\n')

for i in range(data.shape[1]):
	f.write(str(int(data[-1][i])))

f.close()

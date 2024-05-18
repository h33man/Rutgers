#Problem 1, practicing KNN

A=[[0,1,0],[0,1,1],[1,2,1],[1,2,0]]
B=[[1,2,2],[2,2,2],[1,2,-1],[2,2,3]]
C=[[-1,-1,-1],[0,-1,-2],[0,-1,1],[-1,-2,1]]
S=[1,0,1]
SA=[[(S[i]-A[j][i])**2 for i in range(len(S))] for j in range(len(A))]
SB=[[(S[i]-B[j][i])**2 for i in range(len(S))] for j in range(len(B))]
SC=[[(S[i]-C[j][i])**2 for i in range(len(S))] for j in range(len(C))]

print(SA)
dA = [round((SA[j][0]+SA[j][1]+SA[j][2])** 0.5,2) for j in range(len(SA))]
dB = [round((SB[j][0]+SB[j][1]+SB[j][2])** 0.5,2) for j in range(len(SB))]
dC = [round((SC[j][0]+SC[j][1]+SC[j][2])** 0.5,2) for j in range(len(SC))]

print(dA, dB, dC)

""" Output
[1.73, 1.41, 2.0, 2.24] [2.24, 2.45, 2.83, 3.0] [3.0, 3.32, 1.41, 2.83]
For k=1, test data is classified as A and C
For k=2, A and C
For k=3, it is classified as A
"""
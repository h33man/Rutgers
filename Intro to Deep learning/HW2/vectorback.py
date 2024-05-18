import torch
import math

W=torch.tensor([[0.1,0.5,0.4],[-0.3,0.8,0.6],[0.7,1.0,-0.2]])
X = torch.tensor([[0.2],[0.5],[0.4]])

F1=torch.mm(W,X)
print("F1 = ", F1)
F2 = torch.sigmoid(F1)
print("F2 = ", F2)
F3 = torch.norm(F2)**2
print("F3 = ", F3)

dF3 = 2 * F2
print("dF3 = ", dF3)
dF2 = F2 * (1-F2) * dF3
print("dF2 = ", dF2)
dW = torch.mm(dF2,torch.t(X))
print("dW = ", dW)
dX = torch.mm(torch.t(W),dF2)
print("dX = ", dX)

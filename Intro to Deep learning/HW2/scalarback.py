import torch
import math

x1 = torch.tensor([1.],requires_grad=True)
x2 = torch.tensor([3.],requires_grad=True)
w1 = torch.tensor([2.],requires_grad=True)
w2 = torch.tensor([-1.],requires_grad=True)

f1 = x1*w1
f2 = x2*w2
f3 = torch.sin(f1)
f4 = torch.cos(f2)
f5 = f3**2
f6 = f4+f5
f7 = f6+2
y = 1/f7
print("y =",y)

df7 = -1/f7**2
print("df7 =",df7)

df6 = df7
df5 = df6
df4 = df6
df3 = 2*f3*df5
print("df6 =",df6)
print("df5 =",df5)
print("df4 =",df4)
print("df3 =",df3)

df2 = -torch.sin(f2)*df4
print("df2 =",df2)
df1 = torch.cos(f1)*df3
print("df1 =",df1)

dx2 = w2*df2
print("dx2 =",dx2)
dw2 = x2*df2
print("dw2 =",dw2)
dx1 = w1*df1
print("dx1 =",dx1)
dw1 = x1*df1
print("dw1 =",dw1)

#f.backward()
#print(x1.grad, x2.grad, w1.grad, w2.grad)

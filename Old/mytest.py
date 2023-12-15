import torch.nn as nn 
import torch.optim as optim

class SimpleDNN(nn.Module): 
    def __init__(self): 
        super(SimpleDNN, self).__init__()
        self.flatten = nn.Flatten()
        self.dense1 = nn.Linear(12, 64)
        self.dropout1 = nn.Dropout(0.5)
        self.dense2 = nn.Linear(64, 32)
        self.dropout2 = nn.Dropout(0.5)
        self.dense3 = nn.Linear(32, 1)


    def forward(self, x): 
        x = self.flatten(x)
        x = torch.sigmoid(self.dense1(x))
        x = self.dropout1(x)
        x = torch.sigmoid(self.dense2(x))
        x = self.dropout2(x)
        x = self.dense3(x)
        #debugging(x)
        return x

class mytest(): 
    def __init__(self): 
        print('u wot m8')
    def test(): 
        print('hello world')


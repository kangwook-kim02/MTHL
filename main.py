import os
import argparse
import time as t
import pandas as pd

from sklearn import preprocessing
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split

from utils.helper2 import *

dap = [
 ('NetML', 'top'), ('NetML', 'fine'),
 ('CICIDS2017', 'top'), ('CICIDS2017', 'fine'),
 ('ISCX_vpn-nonvpn2016', 'top'),
 ('ISCX_vpn-nonvpn2016', 'mid'),
 ('ISCX_vpn-nonvpn2016', 'fine'),
]

for k,v in dap:
    # for model in ['RF', 'kNN', 'MLP']:
    model =  'SVM'
    cmd = 'python3 {}_baseline.py --dataset data/{} --anno {} --submit both --modelname {}'.format(model,k,v,model)
    os.system(cmd)
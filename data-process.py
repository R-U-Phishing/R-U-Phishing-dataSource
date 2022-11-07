import pandas as pd
import Feature
from tqdm import tqdm
import warnings
import time

df = pd.read_csv('/home/ec2-user/workspace/DP/source/data.csv')

data_list = []

for url in tqdm(df['url']):
    data = Feature.total_feature(url)
    
    for list_value in data:
        time.sleep(1)
        data_list.append(list_value)

data = pd.DataFrame(data_list, df['label'])

data.to_csv('ml_data.csv')




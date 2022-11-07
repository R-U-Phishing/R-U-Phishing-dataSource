import pandas as pd
from tld import get_tld
import requests
from tqdm import tqdm
phishing = pd.read_csv("/home/ec2-user/workspace/DP/source/online-valid.csv")
phishing = phishing[:1000]
urls = []
for url in phishing["url"]:
    try:
        tld = get_tld(url, as_object=True)
        urls.append(tld.domain)
    except:
        urls.append(url)
phishing['domain'] = urls
phishing = phishing.drop_duplicates("domain")
status_t = []
for url in tqdm(phishing["url"]):
    try:
        res = requests.head(url, timeout=1)
        status = res.status_code
    except:
        status = 0
    print(status)
    status_t.append(status)

phishing["status"] = status_t
phishing = phishing[phishing['status'] == 200]
phishing['label'] = -1
data = phishing[["url", "label"]]
data.to_csv("/home/ec2-user/workspace/DP/source/data.csv", index=False)

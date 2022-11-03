import re
from Patterns import *
from tld import get_tld
import ssl, socket
from datetime import datetime as dt, timezone
from dateutil.parser import parse
import whois
import requests
from bs4 import BeautifulSoup

def Ip_Address(url):
    ip = re.findall(r'[0-9]{1,3}(\.[0-9]{1,3}){3}', url)
    if ip:
        return -1
    else:
        return 1
def long_Address(url):
    long = len(url)
    if long < 54:
        return 1
    if long <= 75:
        return 0
    return -1
def Shortening_Service(url) :
    match = re.search(short_url, url)
    if match :
        return -1
    else :
        return 1
def at_symbol(url):
    if '@' in url or '%40' in url:
        return -1
    return 1
def double_slash(url):
    if '//' in url[7:]:
        return -1
    return 1
def dash_symbol(url):
    tld = get_tld(url, as_object=True)
    if '-' in tld.domain or '-' in tld.subdomain:
        return -1
    return 1
def having_subDomain(url):
    url = url.replace('www.', '')
    tld = get_tld(url, as_object=True)
    dot = 0
    dot += str(tld).count('.')
    if tld.subdomain:
        dot += 1
        dot += tld.subdomain.count('.')
    if dot <= 1:
        return 1
    if dot == 2:
        return 0
    return -1
def https_connect(url):
    if "https://" in url:
        url = url.replace("https://", "")
    elif "http://" in url:
        url = url.replace("http://", "")
    ctx = ssl.create_default_context()
    s = ctx.wrap_socket(socket.socket(), server_hostname=url)
    s.connect((url, 443))
    return s
def SSLfinal_State(url):
    try:
        s = https_connect(url)
    except:
        return -1
    cert = s.getpeercert()
    notBefore = cert["notBefore"]
    init_date = parse(notBefore)
    now = dt.now()
    total_days = (now.date() - init_date.date()).days
    if total_days >= 365:
        return 1
    return 0
def Domain_registration_length(url):
    domain_info = whois.whois(url)
    expirty_time = domain_info["expiration_date"]
    now = dt.now().date()
    if isinstance(expirty_time, list):
        for expirty in expirty_time:
            end_days = (expirty.date() - now).days
            if end_days > 365:
                return 1
    else:
        end_days = (expirty_time.date() - now).days
        if end_days > 365:
            return 1
    return -1
def Favicon(url):
    req = requests.get(url)
    html = req.text
    soup = BeautifulSoup(html, "html.parser")
    tag_link = soup.find("link", rel=re.compile("^icon$", re.I))
    
    if not tag_link:
        return 0

    tld = get_tld(url, as_object=True)
    domain = tld.domain
    
    if 'http' in tag_link["href"]:
        if domain in tag_link["href"]:
            return 1
        else:
            return -1
    return 1
def HTTPS_token(url):
    tld = get_tld(url, as_object=True)
    domain = tld.domain
    subDomain = tld.subdomain
    if "https" in domain or "https" in subDomain:
        return -1
    return 1
def Request_URL(url):
    req = requests.get(url, verify=False)
    html = req.text
    soup = BeautifulSoup(html, "html.parser")
    tld = get_tld(url, as_object=True)
    domain = tld.domain
    
    aTags = soup.findAll('a', href=True)
    linkTags = soup.findAll('link', href=True)
    imgTags = soup.findAll('img', src=True)
    scriptTags = soup.findAll('script', src=True)
    iframeTags = soup.findAll('iframe', src=True)
    
    total = len(aTags) + len(linkTags) + len(imgTags) + len(scriptTags) + len(iframeTags)
    
    count = 0
    for a in aTags:
        if 'http' in a["href"]:
            if domain not in a["href"]:
                count += 1
    for link in linkTags:
        if 'http' in link["href"]:
            if domain not in link["href"]:
                count += 1
    for img in imgTags:
        if 'http' in img["src"]:
            if domain not in img["src"]:
                count += 1
    for script in scriptTags:
        if 'http' in script["src"]:
            if domain not in script["src"]:
                count += 1
    for iframe in iframeTags:
        if 'http' in iframe["src"]:
            if domain not in iframe["src"]:
                count += 1
                
    score = count / total * 100
    if score < 22:
        return 1
    elif 22 <= score < 61:
        return 0
    else:
        return -1
def URL_of_Anchor(url):
    req = requests.get(url, verify=False)
    html = req.text
    soup = BeautifulSoup(html, "html.parser")
    
    aTags = soup.findAll('a', href=True)
    
    tld = get_tld(url, as_object=True)
    domain = tld.domain
    
    count = 0
    cstr = ['#', '#content', '#skip', 'javascript::void(0)']
    
    for a in aTags:
        href = a["href"]
        if 'http' in href:
            if domain not in href:
                count += 1
        else:
            for c in cstr:
                if c == href:
                    count += 1
                
    score = count / len(aTags) * 100
    if score < 31:
        return 1
    elif 31 <= score < 67:
        return 0
    else:
        return -1
def Links_in_tags(url):
    req = requests.get(url, verify=False)
    html = req.text
    soup = BeautifulSoup(html, "html.parser")
    tld = get_tld(url, as_object=True)
    domain = tld.domain
    
    linkTags = soup.findAll('link', href=True)
    scriptTags = soup.findAll('script', src=True)
    metaTags = soup.findAll('meta', content=True)
    
    total = len(linkTags) + len(scriptTags) + len(metaTags)
    
    count = 0
    for link in linkTags:
        if 'http' in link["href"]:
            if domain not in link["href"]:
                count += 1
    for script in scriptTags:
        if 'http' in script["src"]:
            if domain not in script["src"]:
                count += 1
    for meta in metaTags:
        if 'http' in meta["content"]:
            if domain not in meta["content"]:
                count += 1
                
    score = count / total * 100
    if score < 17:
        return 1
    elif 17 <= score < 81:
        return 0
    else:
        return -1
def SFH(url):
    req = requests.get(url, verify=False)
    html = req.text
    soup = BeautifulSoup(html, "html.parser")
    tld = get_tld(url, as_object=True)
    domain = tld.domain
    
    formTags = soup.findAll('form', action=True)
    if not formTags:
        return 0
    
    form = formTags[0]
    if form["action"].replace(' ','')  == "about:blank":
        return -1
    if 'http' in form["action"]:
        if domain not in form["action"]:
            return 0
    return 1
def Abnormal_URL(url):
    tld = get_tld(url, as_object=True)
    domain = tld.domain
    
    domain_info = whois.whois(url)
    try:
        if domain.lower() in domain_info['org'].lower():
            return 1
        return -1
    except:
        return 0
def Age_of_Domain(url):
    domain_info = whois.whois(url)
    create_time = domain_info["creation_date"]
    
    now = dt.now().date()
    if isinstance(create_time, list):
        for create in create_time:
            age_days = (now - create.date()).days
            if age_days >= 180:
                return 1
    else:
        age_days = (now - create_time.date()).days
        if age_days >= 180:
            return 1
    return -1
def DNS_Record(url):
    try:
        whois.whois(url)
    except:
        return -1
    return 1
def PageRank(url):
    data = {"name":url}
    req = requests.post("https://checkpagerank.net/check-page-rank.php", data=data)
    html = req.text
    soup = BeautifulSoup(html, "html.parser")
    
    rank = soup.findAll("font", {"color":"#000099"})[1]
    PageRank = rank.text
    PageRank = int(PageRank.replace("/10", ""))
    
    if PageRank / 10 < 0.2:
        return -1
    else:
        return 1
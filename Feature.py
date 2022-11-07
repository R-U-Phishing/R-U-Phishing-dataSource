import re
from Patterns import *
from tld import get_tld
import ssl, socket
from datetime import datetime as dt, timezone
from dateutil.parser import parse
import whois
import requests
from bs4 import BeautifulSoup
import warnings

def Ip_Address(url, req, tld, domain_info):
    ip = re.findall(r'[0-9]{1,3}(\.[0-9]{1,3}){3}', url)
    if ip:
        return -1
    else:
        return 1
def long_Address(url, req, tld, domain_info):
    long = len(url)
    if long < 54:
        return 1
    if long <= 75:
        return 0
    return -1
def Shortening_Service(url,req,tld,domain_info):
    match = re.search(short_url, url)
    if match :
        return -1
    else :
        return 1
def at_symbol(url, req, tld, domain_info):
    if '@' in url or '%40' in url:
        return -1
    return 1
def double_slash(url, req, tld, domain_info):
    if '//' in url[7:]:
        return -1
    return 1
def dash_symbol(url, req, tld, domain_info):
    tld = get_tld(url, as_object=True, fix_protocol=True)
    if '-' in tld.domain or '-' in tld.subdomain:
        return -1
    return 1
def having_subDomain(url, req, tld, domain_info):
    url = url.replace('www.', '')
    tld = get_tld(url, as_object=True, fix_protocol=True)
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
def https_connect(url, req, tld, domain_info):
    if "https://" in url:
        url = url.replace("https://", "")
    elif "http://" in url:
        url = url.replace("http://", "")
    ctx = ssl.create_default_context()
    s = ctx.wrap_socket(socket.socket(), server_hostname=url)
    s.connect((url, 443))
    return s
def SSLfinal_State(url, req, tld, domain_info):
    try:
        s = https_connect(url, req, rld, domain_info)
    except:
        return -1
    cert = s.getpeercert()
    notBefore = cert["notBefore"]
    try:
        init_date = parse(notBefore)
        now = dt.now()
        total_days = (now.date() - init_date.date()).days
    except:
        return -1
    if total_days >= 365:
        return 1
    return 0
def Domain_registration_length(url, req, tld, domain_info):
    try:
        expirty_time = domain_info["expiration_date"]
    except:
        return -1
    now = dt.now().date()
    if isinstance(expirty_time, list):
        for expirty in expirty_time:
            end_days = (expirty.date() - now).days
            if end_days > 365:
                return 1
    else:
        try:
            end_days = (expirty_time.date() - now).days
        except: 
            return -1
        if end_days > 365:
            return 1
    return -1
def Favicon(url, req, tld, domain_info):
    try:
        req = requests.get(url, verify=False)
    except:
        req = requests.get("http://"+url, verify=False)
    html = req.text
    soup = BeautifulSoup(html, "html.parser")
    tag_link = soup.find("link", rel=re.compile("^icon$", re.I))

    if not tag_link:
        return 0

    tld = get_tld(url, as_object=True, fix_protocol=True)
    domain = tld.domain
    try:
        if 'http' in tag_link["href"]:
            if domain in tag_link["href"]:
                return 1
            else:
                return -1
    except:
        return -1
    return 1
def HTTPS_token(url, req, tld, domain_info):
    tld = get_tld(url, as_object=True, fix_protocol=True)
    domain = tld.domain
    subDomain = tld.subdomain
    if "https" in domain or "https" in subDomain:
        return -1
    return 1
def Request_URL(url, req, tld, domain_info):
    try:
        req = requests.get(url, verify=False)
    except:
        req = requests.get("http://"+url, verify=False)
    html = req.text
    soup = BeautifulSoup(html, "html.parser")
    tld = get_tld(url, as_object=True, fix_protocol=True)
    domain = tld.domain

    aTags = soup.findAll('a', href=True)
    linkTags = soup.findAll('link', href=True)
    imgTags = soup.findAll('img', src=True)
    scriptTags = soup.findAll('script', src=True)
    iframeTags = soup.findAll('iframe', src=True)

    total = len(aTags) + len(linkTags) + len(imgTags) + len(scriptTags) + len(iframeTags)

    count = 0
    try:
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
    except:
        return -1
    try:
        score = count / total * 100
    except:
        return -1

    if score < 22:
        return 1
    elif 22 <= score < 61:
        return 0
    else:
        return -1
def URL_of_Anchor(url, req, tld, domain_info):
    try:
        req = requests.get(url, verify=False)
    except:
        req = requests.get("http://"+url, verify=False)
    html = req.text
    soup = BeautifulSoup(html, "html.parser")

    aTags = soup.findAll('a', href=True)

    tld = get_tld(url, as_object=True, fix_protocol=True)
    domain = tld.domain

    count = 0
    cstr = ['#', '#content', '#skip', 'javascript::void(0)']
    try:
        for a in aTags:
            href = a["href"]
            if 'http' in href:
                if domain not in href:
                    count += 1
            else:
                for c in cstr:
                    if c == href:
                        count += 1
    except:
        return -1
    try:
        score = count / len(aTags) * 100
    except:
            return -1
    if score < 31:
        return 1
    elif 31 <= score < 67:
        return 0
    else:
        return -1
def Links_in_tags(url, req, tld, domain_info):
    try:
        req = requests.get(url, verify=False)
    except:
        req = requests.get("http://"+url, verify=False)
    html = req.text
    soup = BeautifulSoup(html, "html.parser")
    tld = get_tld(url, as_object=True, fix_protocol=True)
    domain = tld.domain

    linkTags = soup.findAll('link', href=True)
    scriptTags = soup.findAll('script', src=True)
    metaTags = soup.findAll('meta', content=True)

    total = len(linkTags) + len(scriptTags) + len(metaTags)

    count = 0
    try:
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
    except:
        return -1

    try:
        score = count / total * 100
    except:
        return -1
    if score < 17:
        return 1
    elif 17 <= score < 81:
        return 0
    else:
        return -1
def SFH(url, req, tld, domain_info):
    try:
        req = requests.get(url, verify=False)
    except:
        req = requests.get("http://"+url, verify=False)
    html = req.text
    soup = BeautifulSoup(html, "html.parser")
    tld = get_tld(url, as_object=True, fix_protocol=True)
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
def Abnormal_URL(url, req, tld, domain_info):
    tld = get_tld(url, as_object=True, fix_protocol=True)
    domain = tld.domain

    try:
        if domain.lower() in domain_info['org'].lower():
            return 1
        return -1
    except:
        return 0
def Age_of_Domain(url, req, tld, domain_info):
    try:
        create_time = domain_info["creation_date"]
    except:
        return -1

    now = dt.now().date()
    if isinstance(create_time, list):
        for create in create_time:
            try:
                age_days = (now - create.date()).days
                if age_days >= 180:
                    return 1
            except:
                return -1
    else:
        try:
            age_days = (now - create_time.date()).days
            if age_days >= 180:
                return 1
        except:
            return -1
    return -1
def DNS_Record(url, req, tld, domain_info):
    try:
        whois.whois(url)
    except:
        return -1
    return 1

def total_feature(url):
    data_list = []
    try:
        req = requests.get(url, verify=False)
    except:
        req = requests.get("http://"+url, verify=False)

    tld = get_tld(url, as_object=True, fix_protocol=True)
    
    try:
        domain_info = whois.whois(url)
    except:
        domain_info = -1
        data_list.append([Ip_Address(url, req, tld, domain_info) ,long_Address(url, req, tld, domain_info) ,Shortening_Service(url, req, tld, domain_info) ,at_symbol(url, req, tld, domain_info) ,double_slash(url, req, tld, domain_info) ,dash_symbol(url, req, tld, domain_info) ,having_subDomain(url, req, tld, domain_info)  ,SSLfinal_State(url, req, tld, domain_info) ,-1 ,Favicon(url, req, tld, domain_info) ,HTTPS_token(url, req, tld, domain_info) ,Request_URL(url, req, tld, domain_info) ,URL_of_Anchor(url, req, tld, domain_info) ,Links_in_tags(url, req, tld, domain_info) ,SFH(url, req, tld, domain_info) ,-1 ,-1 ,-1])
        return data_list

    data_list.append([Ip_Address(url, req, tld, domain_info) ,long_Address(url, req, tld, domain_info) ,Shortening_Service(url, req, tld, domain_info) ,at_symbol(url, req, tld, domain_info) ,double_slash(url, req, tld, domain_info) ,dash_symbol(url, req, tld, domain_info) ,having_subDomain(url, req, tld, domain_info)  ,SSLfinal_State(url, req, tld, domain_info) ,Domain_registration_length(url, req, tld, domain_info) ,Favicon(url, req, tld, domain_info) ,HTTPS_token(url, req, tld, domain_info) ,Request_URL(url, req, tld, domain_info) ,URL_of_Anchor(url, req, tld, domain_info) ,Links_in_tags(url, req, tld, domain_info) ,SFH(url, req, tld, domain_info) ,Abnormal_URL(url, req, tld, domain_info) ,Age_of_Domain(url, req, tld, domain_info) ,1])
    return data_list


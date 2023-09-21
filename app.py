from flask import Flask, render_template, request
import re
import pickle
import os
import numpy as np
from urllib.parse import urlparse
from googlesearch import search
import pandas as pd
app=Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")


    
def having_ip_address(url):
    match = re.search(
    '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
    '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
    '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
    '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
    if match:
        return 1
    else:
        return 0    
    
def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    if match:
        return 1
    else:
        return 0

def google_index(url):
    site = search(url, 5)
    if site:
        return 1
    else:
        return 0
        
def count_dot(url):
    count_dot = url.count('.')
    return count_dot

def count_www(url):
    return url.count('www')

def count_atrate(url):
    return url.count('@')

def no_of_dir(url):
    urldir = urlparse(url).path
    return urldir.count('/')

def no_of_embed(url):
    urldir = urlparse(url).path
    return urldir.count('//')

def shortening_service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
    'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
    'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
    'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
    'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
    'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
    'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
    'tr\.im|link\.zip\.net',
    url)
    if match:
        return 1
    else:
        return 0
    
def count_https(url):
    return url.count('https')

def count_http(url):
    return url.count('http')

def count_per(url):
    return url.count('%')

def count_ques(url):
    return url.count('?')

def count_hyphen(url):
    return url.count('-')

def count_equal(url):
    return url.count('=')

def url_length(url):
    return len(str(url))

def hostname_length(url):
    return len(urlparse(url).netloc)

def suspicious_words(url):
    match = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr',
    url)
    if match:
        return 1
    else:
        return 0
    
def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits

def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
    return letters

def fd_length(url):
    urlpath= urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0
    
@app.route("/result",methods=['POST','GET'])
def result():
    url=request.form.get("url")
    l=[]
    l.append(having_ip_address(url))
    l.append(abnormal_url(url))
    l.append(google_index(url))
    l.append(count_dot(url))
    l.append(count_www(url))
    l.append(count_atrate(url))
    l.append(no_of_dir(url))
    l.append(no_of_embed(url))
    l.append(shortening_service(url))
    l.append(count_https(url))
    l.append(count_http(url))
    l.append(count_per(url))
    l.append(count_ques(url))
    l.append(count_hyphen(url))
    l.append(count_equal(url))
    l.append(url_length(url))
    l.append(hostname_length(url))
    l.append(suspicious_words(url))
    l.append(digit_count(url))
    l.append(letter_count(url))
    l.append(fd_length(url))
    dbfile = open(r'C:/Users/vamshi/Desktop/SIH/models/rf.pkl', 'rb')
    db = pickle.load(dbfile)
    predicted_price = db.predict(np.array([l]).reshape(1,-1))
    t=int(predicted_price[0])
    type=""
    if t==0:
        type="Malware"
    elif t==1:
        type="safe"
    elif t==2:
        type="safe"
    elif url=='https://anurag.edu.in/':
        type="safe"
    elif t==3:
        type="Phishing"    
    else:
        type="Invalid Link"    
    return render_template("temp.html",s=url,ty=type) 
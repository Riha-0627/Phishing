import pandas as pd
import requests
from urllib.parse import urlparse, urlencode
import ipaddress
import re
from bs4 import BeautifulSoup
import whois
import urllib.request
from datetime import datetime

# Download phishing data
url = "http://data.phishtank.com/data/online-valid.csv"
filename = "online-valid.csv"
response = requests.get(url)
with open(filename, 'wb') as f:
    f.write(response.content)

# Load phishing data
import pandas as pd

data0 = pd.read_csv(filename, sep=',', quotechar='"')
print(data0.head())

print(data0.head())
print("Phishing data shape:", data0.shape)

# Collect 5,000 phishing URLs randomly
phishurl = data0.sample(n=5000, random_state=12).reset_index(drop=True)

print(phishurl.head())
print("Phishing sample shape:", phishurl.shape)

# Load legitimate URLs data
data1 = pd.read_csv("Benign_list_big_final.csv")
data1.columns = ['URLs']

print(data1.head())

# Collect 5,000 legitimate URLs randomly
legiurl = data1.sample(n=5000, random_state=12).reset_index(drop=True)

print(legiurl.head())
print("Legitimate sample shape:", legiurl.shape)

# 1. Domain of the URL (Domain)
def getDomain(url):
    domain = urlparse(url).netloc
    if domain.startswith("www."):
        domain = domain.replace("www.", "")
    return domain

# 2. Checks for IP address in URL (Have_IP)
def havingIP(url):
    domain = urlparse(url).netloc
    try:
        ipaddress.ip_address(domain)
        return 1
    except:
        return 0

# 3. Checks the presence of '@' in URL (Have_At)
def haveAtSign(url):
    return 1 if "@" in url else 0

# 4. Finding the length of URL and categorizing (URL_Length)
def getLength(url):
    return 0 if len(url) < 54 else 1

# 5. Gives number of '/' in URL (URL_Depth)
def getDepth(url):
    path = urlparse(url).path
    depth = len([x for x in path.split('/') if x])
    return depth

# 6. Checking for redirection '//' in the url (Redirection)
def redirection(url):
    pos = url.rfind('//')
    if pos > 6:
        return 1 if pos > 7 else 0
    else:
        return 0

# 7. Existence of "HTTPS" Token in Domain (https_Domain)
def httpDomain(url):
    domain = urlparse(url).netloc
    return 1 if 'https' in domain else 0

# Shortening services pattern
shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"

# 8. Checking for Shortening Services in URL (Tiny_URL)
def tinyURL(url):
    return 1 if re.search(shortening_services, url) else 0

# 9. Checking for Prefix or Suffix Separated by '-' in Domain (Prefix/Suffix)
def prefixSuffix(url):
    domain = urlparse(url).netloc
    return 1 if '-' in domain else 0

# 12. Web traffic (Web_Traffic)
def web_traffic(url):
    try:
        encoded_url = urllib.parse.quote(url)
        alexa_xml = urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + encoded_url).read()
        rank = BeautifulSoup(alexa_xml, "xml").find("REACH")['RANK']
        rank = int(rank)
    except Exception:
        return 1  # suspicious if cannot fetch rank
    return 1 if rank < 100000 else 0

# 13. Survival time of domain: difference between termination and creation time (Domain_Age)
def domainAge(domain_name):
    creation_date = domain_name.creation_date
    expiration_date = domain_name.expiration_date

    # Handle lists or strings for dates
    if isinstance(creation_date, list):
        creation_date = creation_date[0]
    if isinstance(expiration_date, list):
        expiration_date = expiration_date[0]

    if isinstance(creation_date, str):
        try:
            creation_date = datetime.strptime(creation_date.split(' ')[0], '%Y-%m-%d')
        except:
            return 1
    if isinstance(expiration_date, str):
        try:
            expiration_date = datetime.strptime(expiration_date.split(' ')[0], '%Y-%m-%d')
        except:
            return 1

    if not creation_date or not expiration_date:
        return 1

    age_of_domain = (expiration_date - creation_date).days
    return 1 if (age_of_domain / 30) < 6 else 0

# 14. End time of domain: difference between expiration date and current time (Domain_End)
def domainEnd(domain_name):
    expiration_date = domain_name.expiration_date

    if isinstance(expiration_date, list):
        expiration_date = expiration_date[0]

    if isinstance(expiration_date, str):
        try:
            expiration_date = datetime.strptime(expiration_date.split(' ')[0], '%Y-%m-%d')
        except:
            return 1

    if not expiration_date:
        return 1

    today = datetime.now()
    end = (expiration_date - today).days
    return 0 if (end / 30) < 6 else 1

# 15. IFrame Redirection (iFrame)
def iframe(response):
    if response == "" or not hasattr(response, "text"):
        return 1
    if re.search(r"<iframe|<frameBorder", response.text, re.IGNORECASE):
        return 0
    else:
        return 1

# 16. Checks effect of mouse over on status bar (Mouse_Over)
def mouseOver(response):
    if response == "" or not hasattr(response, "text"):
        return 1
    if re.search(r"<script>.+onmouseover.+</script>", response.text, re.IGNORECASE | re.DOTALL):
        return 1
    else:
        return 0

# 17. Checks the status of the right click attribute (Right_Click)
def rightClick(response):
    if response == "" or not hasattr(response, "text"):
        return 1
    if re.search(r"event.button ?== ?2", response.text):
        return 0
    else:
        return 1

# 18. Checks the number of forwardings (Web_Forwards)
def forwarding(response):
    if response == "" or not hasattr(response, "history"):
        return 1
    return 0 if len(response.history) <= 2 else 1

# Main feature extraction function
def featureExtraction(url, label):
    features = []
    features.append(getDomain(url))
    features.append(havingIP(url))
    features.append(haveAtSign(url))
    features.append(getLength(url))
    features.append(getDepth(url))
    features.append(redirection(url))
    features.append(httpDomain(url))
    features.append(tinyURL(url))
    features.append(prefixSuffix(url))

    dns = 0
    try:
        domain_name = whois.whois(urlparse(url).netloc)
    except Exception:
        dns = 1
        domain_name = None

    features.append(dns)
    features.append(web_traffic(url))
    features.append(1 if dns == 1 else domainAge(domain_name))
    features.append(1 if dns == 1 else domainEnd(domain_name))

    try:
        response = requests.get(url, timeout=5)
    except Exception:
        response = ""

    features.append(iframe(response))
    features.append(mouseOver(response))
    features.append(rightClick(response))
    features.append(forwarding(response))
    features.append(label)

    return features

# Extract features for legitimate URLs
legi_features = []
label = 0
for url in legiurl['URLs']:
    legi_features.append(featureExtraction(url, label))

feature_names = ['Domain', 'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection',
                 'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic',
                 'Domain_Age', 'Domain_End', 'iFrame', 'Mouse_Over', 'Right_Click', 'Web_Forwards', 'Label']

legitimate = pd.DataFrame(legi_features, columns=feature_names)
print(legitimate.head())

# Save legitimate features to CSV
legitimate.to_csv('legitimate.csv', index=False)

# Extract features for phishing URLs
phish_features = []
label = 1
for url in phishurl['url']:
    phish_features.append(featureExtraction(url, label))

phishing = pd.DataFrame(phish_features, columns=feature_names)
print(phishing.head())

# Save phishing features to CSV
phishing.to_csv('phishing.csv', index=False)

# Combine dataframes
urldata = pd.concat([legitimate, phishing]).reset_index(drop=True)
print(urldata.head())
print(urldata.tail())
print("Combined data shape:", urldata.shape)

# Save combined data to CSV
urldata.to_csv('urldata.csv', index=False)

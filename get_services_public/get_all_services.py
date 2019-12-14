'''
Quick Program to get a list of services that have public IP Ranges

@author: colin bitterfield
'''
import requests
import numpy as np 

SERVICE_LIST = []

ip_ranges = requests.get('https://ip-ranges.amazonaws.com/ip-ranges.json').json()['prefixes']
amazon_ips = [item['ip_prefix'] for item in ip_ranges if item["service"] == "AMAZON"]
ec2_ips = [item['ip_prefix'] for item in ip_ranges if item["service"] == "EC2"]


for item in ip_ranges:
    if item["service"] != "AMAZON": SERVICE_LIST.append(item["service"])

SERVICE_ARRAY = np.array(SERVICE_LIST) 
SERVICES = (np.unique(SERVICE_ARRAY)) 

for SERVICE in SERVICES:
    print(SERVICE)


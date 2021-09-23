from dnsresolver import *
from dnssecresolver import *
import numpy as np
import matplotlib.pyplot as plt
#%matplotlib inline

sites = [
    'google.com',
    'youtube.com',
    'bing.com',
    'amazon.in',
    'ebay.com',
    'sohu.com',
    'facebook.com',
    'twitch.tv',
    'microsoftonline.com',
    'yahoo.co.jp',
    'amazon.com',
    'yahoo.com',
    'wikipedia.org',
    'weibo.com',
    'linkedin.com',
    'zoom.us',
    'sharepoint.com',
    'live.com',
    'netflix.com',
    'reddit.com',
    'microsoft.com',
    'instagram.com',
    'office.com',
    'google.com.hk',
    'panda.tv'
]

"""
import re
import subprocess
import shlex



resolver = DNSResolver()

# Experiment 1: Run your DNS resolver on each website 10 times, and 
# find the average time to resolve the DNS for each of the 25 websites.
exp1_timings = []

for site in sites:
    total_query_time = 0
    for i in range(10):
        response = resolver.resolve(site, "A")
        query_time = int(re.findall(r'Query time: (.*?) msec', response)[0])
        total_query_time += query_time
    avg_time = total_query_time/10 
    exp1_timings += [avg_time]

print("Experiment 1: ", exp1_timings)

# Experiment 2: Now use your local DNS resolver and repeat the experiment (state the name of the DNS resolver you used). 
# Find the average time to resolve the address for the 25 websites, computed as the average over 10 runs.
exp2_timings = []

for site in sites:
    total_query_time = 0
    for i in range(10):
        cmd = f"dig {site} A"
        proc = subprocess.Popen(shlex.split(cmd),stdout=subprocess.PIPE)
        response, err=proc.communicate()
        query_time = int(re.findall(r'Query time: (.*?) msec', response.decode())[0])
        total_query_time += query_time
    avg_time = total_query_time/10 
    exp2_timings += [avg_time]

print("Experiment 2: ", exp2_timings)

# Experiment 3: Change the DNS resolver to Google’s public DNS 
# (The IP address of this public DNS is often 8.8.8.8, or 8.8.4.4, but you need to verify). 
# Repeat the experiment one more time.

exp3_timings = []

for site in sites:
    total_query_time = 0
    for i in range(10):
        cmd = f"dig @8.8.8.8 {site} A"
        proc = subprocess.Popen(shlex.split(cmd),stdout=subprocess.PIPE)
        response, err=proc.communicate()
        query_time = int(re.findall(r'Query time: (.*?) msec', response.decode())[0])
        total_query_time += query_time
    avg_time = total_query_time/10 
    exp3_timings += [avg_time]


print("Experiment 3: ", exp3_timings)
"""

"""  
References:
-----------
https://www.geeksforgeeks.org/how-to-calculate-and-plot-a-cumulative-distribution-function-with-matplotlib-in-python/
"""

exp1_timings =  [45.6, 45.2, 32.0, 39.1, 32.1, 282.7, 43.8, 33.2, 113.5, 533.2, 38.3, 33.7, 228.5, 286.7, 31.5, 28.9, 41.2, 114.2, 38.2, 31.8, 33.7, 40.5, 113.9, 287.5, 255.0]
exp2_timings =  [2.8, 2.8, 2.0, 1.6, 1.7, 27.1, 1.2, 1.6, 1.8, 1.2, 1.8, 2.1, 1.6, 26.0, 1.7, 2.3, 2.1, 2.3, 1.7, 1.6, 2.3, 1.7, 1.7, 4.9, 2.0]
exp3_timings =  [1.4, 1.9, 5.4, 1.7, 1.0, 139.0, 5.0, 4.3, 1.5, 1.1, 0.8, 0.4, 1.7, 224.8, 3.5, 2.6, 1.1, 0.9, 2.9, 1.0, 0.5, 1.5, 1.2, 1.6, 1.0]

def plot(exp1_timings, exp2_timings, exp3_timings):
    # initializing random values
    data1 = np.array(exp1_timings)
    data2 = np.array(exp2_timings)
    data3 = np.array(exp3_timings)
    
    # getting data of the histogram
    count1, bins_count1 = np.histogram(data1, bins=10)
    count2, bins_count2 = np.histogram(data2, bins=10)
    count3, bins_count3 = np.histogram(data3, bins=10)
    
    # finding the PDF of the histogram using count values
    pdf1 = count1 / sum(count1)
    pdf2 = count2 / sum(count2)
    pdf3 = count3 / sum(count3)
    
    # using numpy np.cumsum to calculate the CDF
    # We can also find using the PDF values by looping and adding
    cdf1 = np.cumsum(pdf1)
    cdf2 = np.cumsum(pdf2)
    cdf3 = np.cumsum(pdf3)
    
    # plotting PDF and CDF
    plt.plot(bins_count1[1:], cdf1, label="mydig", color="red")
    plt.plot(bins_count2[1:], cdf2, label="Local DNS Server", color="blue")
    plt.plot(bins_count3[1:], cdf3, label="Google's DNS Resolver", color="green")
    plt.legend()
    plt.xlabel("Query resolution time (msec)")
    plt.ylabel("Probabilities")
    plt.show()

#plot(exp1_timings, exp2_timings, exp3_timings)

report = ""
report += "| {:20} | {:5} | {:9} | {:12} |\n".format("Sites", "Mydig", "Local DNS", "Google's DNS")

n = len(report)
report += "="*(n-1)+"\n"
report = "="*(n-1)+"\n" + report

for i,site in enumerate(sites):
    report += "| {:20} | {:^5} | {:^9} | {:^12} |\n".format(site, str(exp1_timings[i]), str(exp2_timings[i]), str(exp3_timings[i]))
    if i!=len(sites)-1:
        report += "-"*(n-1)+"\n"

report += "="*(n-1)+"\n"

print(report)
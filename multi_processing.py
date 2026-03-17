import threading as multi_processing
from bs4 import BeautifulSoup
import requests

urls=[
    'https://www.wikipedia.org',
    'https://www.github.com',
    'https://www.stackoverflow.com',
    'https://www.reddit.com',
    'https://www.medium.com',
    'https://www.quora.com',
]

def fetch_url(url):
    response=requests.get(url)
    soup=BeautifulSoup(response.content,'html.parser')
    print(f'fetched {len(soup.text)} characters from {url}')
threads=[]
for url in urls:
    thread=multi_processing.Thread(target=fetch_url,args=(url,))
    threads.append(thread)
    thread.start()
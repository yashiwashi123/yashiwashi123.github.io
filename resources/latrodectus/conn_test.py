import requests
real_url = ""
url = "http://example.com"
headers = {
    'User-Agent': "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.10136",
    'Accept-Encoding': "",
    'Content-Type': 'application/octect-stream',
    'Authorization': 'Basic MzM5MzQzNjMwMzozOTk3MDYwMTkwOjEyMDo2NjoxNg==',
    'Cookie': 'session=MDowOjA6MTI5ODc6MA='
    }

'''
Enrcryption Key: qNfSHTVKEU7mknHSFrQCwp0mmQfXUNPIcA66gezNz49qQOVX0P

Things to set: 

Group
Version
Direction

'''

'''

counter=0&type=1&guid=01B10D63A93595915DB96521ADC9&os=6&arch=1&username=yashiwashi&group=2296796206&ver=1.3&up=2&direction=https://ultroawest.com/live/

rc4 and 64 : hcyeNY2LALy8fz5kBNZjkK+KOo+UvgK8nSBRO5D9ZpMQ0OJqPB/lQJGirCtvXbUQKQ3SzTnHiCOX+2Mf1KJ8GNUPfADz3RvcjGDPEOOgj6gysVDDnaf8QEKc/47tYX6Jh0WtWB1by2frDUXLamFv/I2OnnZZYK++tOLXcGIRic0TDY8bUCTGV5TlRxWDFtnHgHtczx51hg==
'''

data = "test"
data = data.encode('utf-8')

r = requests.post(url, headers = headers, data = data)
print (r.text)

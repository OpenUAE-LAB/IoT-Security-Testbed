#code to check IP address
import requests
import os,sys


IPadder= sys.argv[1]

data = {'host':IPadder, 'action':'blacklist-check'}

headers={ 'X-Requested-With':'XMLHttpRequest',
'Referer':'https://www.whatismyip.com/blacklist-check/', 
'User-Agent':'Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0'}


try:
	respo=requests.post('https://www.whatismyip.com/custom/response.php', data=data, headers=headers)

	with open("./results/CheckIP_"+IPadder+".html", 'w') as file:
		file.write(respo.text)
except():
	print("Error")

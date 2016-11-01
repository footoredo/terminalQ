# coding: utf-8
import json
import requests
import pyqrcode
import qrtools
import re
import time
import psutil
from PIL import Image
from io import BytesIO

s = requests.session()

def verification_status():
	url = "https://ssl.ptlogin2.qq.com/ptqrlogin?webqq_type=10&remember_uin=1&login2qq=1&aid=501004106&u1=http%3A%2F%2Fw.qq.com%2Fproxy.html%3Flogin2qq%3D1%26webqq_type%3D10&ptredirect=0&ptlang=2052&daid=164&from_ui=1&pttype=1&dumy=&fp=loginerroralert&action=0-0-10178&mibao_css=m_webqq&t=undefined&g=1&js_type=0&js_ver=10178&login_sig=&pt_randsalt=0"
	r = s.get(url = url);
#return list(re.finditer(regex, r.content))[4].group(2)
	return r.content

def hide_image():
# not working -_-
	for proc in psutil.process_iter():
		if proc.name() == "display":
			proc.kill()

def get_qrcode():
	hide_image()
	r = s.get("https://ssl.ptlogin2.qq.com/ptqrshow?appid=501004106&e=0&l=M&s=5&d=72&v=4&t=0.1")
	i = Image.open(BytesIO(r.content))
	i.show()
#	i.save('a.png')

#	qr = qrtools.QR()
#	qr.decode('a.png')
#	print(pyqrcode.create(qr.data, error='L').terminal(quiet_zone=1))

get_qrcode()
url = ""
while (True):
	status = verification_status()
#	print status
	if status.find("已失效") != -1:
		get_qrcode()
	elif status.find("http") != -1:
		hide_image()
		regex = r"(\'(.*?)\')+?";
		matches = list(re.finditer(regex, status))
		url = matches[2].group(2);
		user = matches[5].group(2);
		break
	time.sleep(0.8)

print "welcome, %s!" % user
r = s.get(url = url, allow_redirects = False)
ptwebqq = s.cookies['ptwebqq']

r = s.get("http://s.web2.qq.com/api/getvfwebqq?ptwebqq=%s&clientid=53999199&psessionid=&t=1477913618026" % ptwebqq, headers = {'referer': 'http://s.web2.qq.com/proxy.html?v=20130916001&callback=1&id=1'})
vfwebqq = r.json()['result']['vfwebqq']

while (True):
	data = {
		"ptwebqq": ptwebqq,
		"clientid": 53999199,
		"psessionid": "",
		"status": "online"
	}
	r = s.post("http://d1.web2.qq.com/channel/login2", headers = {"referer": "http://d1.web2.qq.com/proxy.html?v=20151105001&callback=1&id=2"},
			data = {"r": json.dumps(data)})
	if r.status_code == 200 and 'result' in r.json():
		uin = r.json()['result']['uin']
		psessionid = r.json()['result']['psessionid']
		break

def send_msg(user_id, msg):
	data = {
    "to": user_id,
    "content": json.dumps([
        msg,
        [
            "font",
            {
                "name": "微软雅黑",
                "size": 10,
                "style": [
                    0,
                    0,
                    0
                ],
                "color": "000000"
            }
        ]
    ], ensure_ascii = False, encoding='utf8'),
    "face": 522,
    "clientid": 53999199,
    "msg_id": 65890001,
    "psessionid": psessionid,
}
	#print json.dumps(data, ensure_ascii=False)

	r = s.post("https://d1.web2.qq.com/channel/send_buddy_msg2", headers = {"referer": "https://d1.web2.qq.com/cfproxy.html?v=20151105001&callback=1"}, data = {"r": json.dumps(data, ensure_ascii=False)})
	print r.content
	if r.status_code != 200 or "errmsg" in r.json():
		time.sleep(0.2)
		send_msg(user_id, msg)

def get_hash():
  n = [0, 0, 0, 0]
  for i in range(0, len(ptwebqq)):
	  n[i % 4] ^= ord(ptwebqq[i])
  u = ['EC', 'OK']
  v = [0, 0, 0, 0]
  v[0] = uin >> 24 & 255 ^ ord(u[0][0])
  v[1] = uin >> 16 & 255 ^ ord(u[0][1])
  v[2] = uin >> 8 & 255 ^ ord(u[1][0])
  v[3] = uin & 255 ^ ord(u[1][1])
  u = [0, 0, 0, 0, 0, 0, 0, 0]
  for i in range(0, 8):
	  if i % 2 == 1:
		  u[i] = v[i >> 1]
	  else:
		  u[i] = n[i >> 1]
  n = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F']
  v = ''
  for i in range(0, 8):
    v += n[(u[i] >> 4) & 15]
    v += n[u[i] & 15]
  return v

def get_friends_list():
	data = {
    	"vfwebqq": vfwebqq,
    	"hash": get_hash()
		}
	r = s.post("http://s.web2.qq.com/api/get_user_friends2",
		headers = {"referer": "http://s.web2.qq.com/proxy.html?v=20130916001&callback=1&id=1"},
		data = {"r": json.dumps(data)})
	return r.json()['result']['marknames']

friends = get_friends_list()
hash_table = {}
hash_table_rev = {}
for friend in friends:
	#print friend["markname"], friend["uin"]
	hash_table[friend["markname"].encode('utf8')] = friend["uin"]
	hash_table_rev[friend["uin"]] = friend["markname"].encode('utf8')

def get_name():
	while (True):
		name = raw_input("Markname> ")
		if name in hash_table:
			print hash_table[name]
			break
	return name

def get_msg():
	data = {
	    "ptwebqq": ptwebqq,
	    "clientid": 53999199,
	    "psessionid": psessionid,
	    "key": ""
	}
	r = s.post("http://d1.web2.qq.com/channel/poll2",
		headers = {"referer": "http://d1.web2.qq.com/proxy.html?v=20151105001&callback=1&id=2"},
		data = {"r": json.dumps(data)})
	if r.status_code != 200 or not "result" in r.json():
		time.sleep(0.2)
		get_msg()
	else:
		for msg in r.json()['result']:
			if (msg['poll_type'] == "message"):
				print hash_table_rev[msg['value']['from_uin']] + "> " + msg['value']['content'][1].encode('utf8')
	#print hash_table_rev[r.json()['result'][0]['value']['from_uin']] + "> " + r.json()['result'][0]['value']['content'][1]

def talk(name):
	the_uin = hash_table[name]
	times = 1
	while (True):
		msg = raw_input('Message> ')
		if msg == "quit":
			break
		elif msg == "listen":
			try:
				while (True):
					get_msg()
					time.sleep(0.2)
			except KeyboardInterrupt:
				pass

		elif msg == "times":
			times = int(raw_input("times> "))
		else:
			for i in range(0, times):
				send_msg(the_uin, msg)

while (True):
	op = raw_input("> ")
	if op == "list":
		for friend in friends:
			print friend["markname"], friend["uin"]
	elif op == "talk":
		talk(get_name())
	elif op == "quit":
		break

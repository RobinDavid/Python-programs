from socket import *
from VideoCapture import Device
import time
import sys

cam = Device()

socket = socket(AF_INET,SOCK_STREAM)
if len(sys.argv) == 1:
	socket.connect(("localhost",7777))
else:
	socket.connect((sys.argv[1],7777))
	
res = cam.getImage().size
socket.send(str(res[0])) #Send webcam resolution
socket.send(str(res[1]))

time.sleep(1)

while True:
	try:
		img = cam.getImage()
		imgstr = img.tostring()
		time.sleep(0.01) #otherwise send to fast and the server receive images in pieces and fail
		socket.send(imgstr)
	except KeyboardInterrupt:
		socket.send("quit")
		socket.close()
		break
	except Exception:
		print("Error from server side")
		socket.close()
		break
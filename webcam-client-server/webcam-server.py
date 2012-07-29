from socket import *
from PIL import ImageFile
import pygame
from pygame.locals import *

#Socket initialisations !
socketServer = socket(AF_INET,SOCK_STREAM)
socketServer.bind(("",7777))
socketServer.listen(1)
socketClient, address = socketServer.accept()

x = socketClient.recv(10) #Recieve webcam resolution to adapt window
y = socketClient.recv(10)
print ("Resolution recieved x=%s, y=%s" % (x,y))

#Pygame initialisations !
pygame.init()
size = (int(x),int(y))
fenetre = (int(x),int(y))
display = pygame.display.set_mode(fenetre)



def process_received_image(data):
	global display
	try:
		camshot = pygame.image.fromstring(data, size, "RGB")
		display.blit(camshot, (0,0))
		pygame.display.flip()
	except ValueError:
		print("Value Error received skip",len(data))


toread= size[0]*size[1]*3 #Each webcam picture should be of the size of width * height * 3 (because each pixel is 3 bytes in RGB)

going = True
while going:
	try:
		data = socketClient.recv(toread)
		if data == "quit" or not data:
			print("Quit received, or no data  received !")
			going=False
		else:
			events = pygame.event.get()
			for e in events:
				if e.type == QUIT or (e.type == KEYDOWN and e.key == K_ESCAPE):
					going = False
			process_received_image(data)
	except KeyboardInterrupt:
		print("Connection closed")
		break

socketClient.close()
socketServer.close()
import pygame
import pygame.camera
from pygame.locals import *
# Simply show the webcam video on a screen

pygame.init()
pygame.camera.init()

cam = pygame.camera.Camera(pygame.camera.list_cameras()[0])
cam.start()

import sys
if sys.platform == "win32":
    from VideoCapture import Device
    tmpcam = Device()
    size = tmpcam.getImage().size
    del tmpcam
else:
    snap = cam.get_image()
    size= (snap.get_width(),snap.get_height())

display = pygame.display.set_mode(size)

snapshot = pygame.surface.Surface(size, 0, display)

def get_and_flip():
	global snapshot, display
	snapshot = cam.get_image(snapshot)
	display.blit(snapshot, (0,0))
	pygame.display.flip()

	
going = True
while going:
	events = pygame.event.get()
	for e in events:
		if e.type == QUIT or (e.type == KEYDOWN and e.key == K_ESCAPE):
			cam.stop()
			going = False

	get_and_flip()

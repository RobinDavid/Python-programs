#!/usr/bin/python
import sys, os
import cv2.cv as cv

class Watermarker:
    def __init__(self, input_filename, output_filename):
        self.prev_pt = None
        self.outname = output_filename
        self.orig = cv.LoadImage(input_filename)
        self.image = cv.CloneImage(self.orig)
        self.chans = self.im_to_lsb()
	cv.ShowImage("image", self.image)
	cv.ShowImage("LSB", self.chans[0])
        cv.SetMouseCallback("image", self.on_mouse)

    def on_mouse(self, event, x, y, flags, param):
        pt = (x, y)
        if event == cv.CV_EVENT_LBUTTONUP or not (flags & cv.CV_EVENT_FLAG_LBUTTON):
            self.prev_pt = None
        elif event == cv.CV_EVENT_LBUTTONDOWN:
            self.prev_pt = pt
        elif event == cv.CV_EVENT_MOUSEMOVE and (flags & cv.CV_EVENT_FLAG_LBUTTON) :
            if self.prev_pt:
                for im in [self.image]+self.chans:
                    cv.Line(im, self.prev_pt, pt, cv.ScalarAll(255), 5, 8, 0)
            self.prev_pt = pt
            cv.ShowImage("image",self.image)
	    cv.ShowImage("LSB",self.chans[0])

    def im_to_lsb(self):
	b = cv.CreateImage(cv.GetSize(self.image), self.image.depth, 1)
	g = cv.CloneImage(b)
	r = cv.CloneImage(b)
	cv.Split(self.image, b, g, r, None)
	for j in range(self.image.height):
	    for i in range(self.image.width):
		pixb,pixg,pixr = self.image[j, i]
		b[j,i] = 255 if int(pixb) & 1 else 0
		g[j,i] = 255 if int(pixg) & 1 else 0
		r[j,i] = 255 if int(pixr) & 1 else 0
	return [b,g,r]

    def save_image(self):
	new = cv.CloneImage(self.orig)
	for j in range(new.height):
	    for i in range(new.width):
		pix = []
		b,g,r = [int(im[j,i]) for im in self.chans]
		curb,curg,curr = [int(x) for x in new[j,i]]
		pix.append(curb | 1 if b == 255 else curb & 254)
		pix.append(curg | 1 if g == 255 else curg & 254)
		pix.append(curr | 1 if r == 255 else curr & 254)
		new[j,i] = tuple(pix)
	cv.SaveImage(self.outname,new)
	
	print "Saved in: "+self.outname

if __name__ == "__main__":
    if len(sys.argv) not in [2,3]:
        print ("./lsbwatermark.py filename [output]")
        sys.exit(1)
    else:
	filename = sys.argv[1]
	base, fname = os.path.split(filename)
	outputname = sys.argv[2] if len(sys.argv) == 3 else (base+"/" if base!="" else "")+"watermarked-"+fname
	if outputname.endswith(".jpg") or outputname.endswith(".jpeg"):
	    print "Warning: File output in .jpeg, will be saved .png instead!"
	    outputname = os.path.splitext(outputname)[0]+".png"

	print "Hot keys:"
	print "\tESC/Ctrl+C - quit the program"
	print "\ts - save the lsb to the image"
	print "\tr - reset the draw on the image"

	try:
	    wt = Watermarker(filename,outputname)
	except IOError as e:
	    print "File:"+filename+" not found !"
	    sys.exit(1)

	while True:
	    c = cv.WaitKey(0) % 0x100
	    if c == 27 or c == ord('q') or c == ord('c'):
		break
	    if c == ord('s'):
		wt.save_image()
	    if c == ord('r'):
		wt = Watermarker(filename,outputname)

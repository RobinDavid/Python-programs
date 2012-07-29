Python-programs
===============

Contains various python programs and proof of concept.

OpenCV colortracking
--------------------

This small program shows how to track a specific color on a webcam using OpenCV.
In this example the color tracked is Yellow.
Article: http://robindavid.comli.com/colortracking-with-opencv/

SMSListener
-----------

This program is articulated around gammu which allow to access mobile phones from a computer.
The advantage of gammu is that it works with quite a lot's of old mobile phone, and is independent of the Operating System.
The purpose of SMSListener is to listen incoming text message and retrieve it's content. In order to do this the phone
should be configured using wammu for instance, and connected. So it provides the structure to remotly control the computer
by allowing the python program to retrieve the message when it is received. So if you implement all the command and control
backend you can fully control your computer via text message even with old mobile phones.
Article: http://robindavid.comli.com/python-gammu-sms-listener/

Webcam Client/Server
--------------------

This program is a small proof of concept of Webcam streaming from a client to a server.
The server once launched wait for a client connection. The client connect to the server and stream the webcam to the server.
The problem is the program use old an old python module to capture the Webcam (VideoCapture) and this module can only run under
Windows. So if I had the time I would have redone it with OpenCV.
Article: http://robindavid.comli.com/simple-clientserver-to-stream-webcam-in-python/

Wikipedia Frequency Analysis
----------------------------

For a cryptography university module we worked on english and french characters frequency tables as we can find on Wikipedia http://en.wikipedia.org/wiki/Frequency_analysis.
But this kind of tables just provide the frequency for the 26 characters of the alphabet. In practice they not usable because
a text contains much more characters, accent, punctuation and so on which are not include in frequency analysis.
So I have decided to create my own one and to get a good text basis what is better than Wikipedia :p ?
So this script use a wikipedia dump read the hole file and count the occurence of each characters.
More informations on this article:  http://robindavid.comli.com/wikipedia-frequency-analysis/

Webcam HTTP
-----------

Webcam http is a small program that shows how to stream webcam in http. It is articulated around VideoCapture (I should change to pygame or whatever), and SimpleHTTPServer.
index.html just include a img tag, and once the script is launched it will regularily take pictures on the webcam and change the src address of the image in index.html.

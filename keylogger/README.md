Infos
-----

Small and efficient keylogger that work with the pyHook module for Windows.
The mechanism is quite easy, pyHook once launched grab all input events, and aside, you need something to grab this hooked events.

There is two way to grab them:

* The first is to use pygame and make and infinite loop on the pygame.event.pump() method
* The second is to use the pythoncom module and call pythoncom.PumpMessages() which do itself an infinite loop waiting for events.

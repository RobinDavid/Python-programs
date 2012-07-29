import pyHook, pythoncom 

def OnMouseEvent(event): # called when mouse events are received
    print "x: "+ str(event.Position[0]) + "\ty:" + str(event.Position[1]) + "  \r",
    '''
    print 'MessageName:',event.MessageName
    print 'Message:',event.Message
    print 'Time:',event.Time
    print 'Window:',event.Window
    print 'WindowName:',event.WindowName
    print 'Position:',event.Position
    print 'Wheel:',event.Wheel
    print 'Injected:',event.Injected
    print '---'
    '''
    return True # return True to pass the event to other handlers

# create a hook manager
hm = pyHook.HookManager()
# watch for all mouse events
hm.MouseAll = OnMouseEvent
# set the hook
hm.HookMouse()
# wait forever
pythoncom.PumpMessages()

#!/usr/bin/python
#Core of the adaptive honeypot alternative
# (c) Gerard Wagener
#License GPL
import os,sys
from pyinotify import *
from ctypes import *
KERNEL_OUT="/home/gerard/kernel/linux-2.6/out"
KERNEL_IN="/home/gerard/kernel/linux-2.6/in"

class ReplyMessage(Structure):
    __fields_ = [ ("block" , c_int), ("exitcode" , c_int), ("substitue" ,c_int),
                  ("insult" , c_int) ]

class KernelEvents(ProcessEvent):
    def silent_clean(self,filename):
        try:
            os.unlink(filename)
        except OSError,e:
            pass

    def create_message(self,filename,block,exitcode,substitue,insult):
        reply = ReplyMessage(block=block,exitcode=exitcode,substitue=substitue,
                             insult = insult)
        fn = KERNEL_IN + os.sep + filename
        f = open (fn,'wb')
        f.write(reply)
        f.close()

    def load_file(self,filename):
        msg = {}
        fp = open(filename,'r')
        for i in fp.read().split('\n'):
            try:
                (key,value) = i.split('=')
            except ValueError,e:
                pass
            if msg.has_key(key) == False:
                msg[key]=[]
            msg[key].append(value)

        fp.close()
        return msg

    def process_IN_CLOSE_WRITE(self, event):
        filename = os.path.join(event.path,event.name)
        msg = self.load_file(filename)
        print msg
        #Send back a message
        self.create_message(event.name, block=23, insult=98,
                            exitcode=1, substitue=55)
        #Cleanup the file
        self.silent_clean(filename)

wm = WatchManager()

mask = IN_CLOSE_WRITE  # watched events

notifier = Notifier(wm, KernelEvents())
wdd = wm.add_watch(KERNEL_OUT, mask, rec=True)

while True:
    try:
        # process the queue of events as explained above
        notifier.process_events()
        if notifier.check_events():
            # read notified events and enqeue them
            notifier.read_events()
    #TODO manage a global queue of unfinished events
    #If inotify on close works this should not be necessary
    except KeyboardInterrupt:
        # destroy the inotify's instance on this interrupt (stop monitoring)
        notifier.stop()
        break


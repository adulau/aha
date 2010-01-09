#!/usr/bin/python
#Core of the adaptive honeypot alternative
# (c) Gerard Wagener
#License GPL
import os,sys,random
from pyinotify import *
from ctypes import *
from ahalib import *
KERNEL_OUT="/home/gerard/kernel/linux-2.6/out"
KERNEL_IN="/home/gerard/kernel/linux-2.6/in"
insultmaxidx = 3


class KernelEvents(ProcessEvent):
    def __init__(self,inqueue,outqueue,insultmaxidx):
        self.ahaa = AHAActions(inqueue,outqueue)

    def decision(self,filekey,msg):
        try:
            command = msg['file'][0]
            print "Got command: ",command
            if msg['file'][0] == '/usr/bin/bvi':
                self.ahaa.create_message(filekey, block=1,
                                    exitcode=KERNEL_ERRORS.ENOMEM,
                                    insult = 0, substitue=0)
                return
            if msg['file'][0] == '/usr/bin/vi':
                # The index 0 is reserved
                idx = random.randint(1,insultmaxidx)
                self.ahaa.create_message(filekey, block=0, exitcode=0,
                                         insult=idx, substitue=0)
                return
        except KeyError,e:
            pass
        except IndexError,w:
            pass
        #Default action; allow-> out of memory
        self.ahaa.create_message(filekey,block=0,exitcode=0,insult=0,
                                 substitue=0)

    def process_IN_CLOSE_WRITE(self, event):
        try:
            filename = os.path.join(event.path,event.name)
            msg = self.ahaa.load_file(filename)
            #Send back a message
            self.decision(event.name,msg)
        except IOError,e:
            sys.stderr.write("Kernel message (%s) could not be loaded or \
                             decison failed\n"%event.name)

if __name__ == '__main__':
    print "Setting up listeners..."

    wm = WatchManager()
    mask = IN_CLOSE_WRITE  # watched events

    notifier = Notifier(wm, KernelEvents(KERNEL_IN,KERNEL_OUT,insultmaxidx))
    wdd = wm.add_watch(KERNEL_OUT, mask, rec=True)

    print "Waiting for events..."
    while True:
        try:
        # process the queue of events as explained above
            notifier.process_events()
            if notifier.check_events():
                # read notified events and enqeue them
                notifier.read_events()
        except KeyboardInterrupt:
        # destroy the inotify's instance on this interrupt (stop monitoring)
            print "Stop listening..."
            notifier.stop()
            break
sys.exit(0)

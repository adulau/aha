#!/usr/bin/python
#Core of the adaptive honeypot alternative
# (c) Gerard Wagener
#License GPL
import os,sys,random
from pyinotify import *
from ctypes import *
KERNEL_OUT="/home/gerard/kernel/linux-2.6/out"
KERNEL_IN="/home/gerard/kernel/linux-2.6/in"

class KERNEL_ERRORS():
    EPERM   = -1
    ENOENT  = -2
    EIO     = -5
    ENOMEM  = -12
    EACESS  = -13
    EFAULT  = -14
    EPIPE   = -32
    ETXTBSY = -26

    def __init__(self):
        self.evec = (EPERM,ENOENT,EIO,ENOMEM,EACESS,EFAULT,EPIPE,ETXTBSY)


class ReplyMessage(Structure):
    _fields_ = [ ("block" , c_int), ("exitcode" , c_int),
                   ("substitue" ,c_int),("insult" , c_int) ]

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
        reply="(key=%s, block=%d,exitcode=%d,substitue=%d,insult=%d)"\
               %(filename,block,exitcode, substitue,insult)
        print reply

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

    def decision(self,filekey,msg):
        insultmaxidx = 3
        print msg
        try:
            command = msg['file'][0]
            print "Got command: ",command
            if msg['file'][0] == '/usr/bin/bvi':
                self.create_message(filekey, block=1,
                                    exitcode=KERNEL_ERRORS.ENOMEM,
                                    insult = 0, substitue=0)
                return
            if msg['file'][0] == '/usr/bin/vi':
                # The index 0 is reserved
                idx = random.randint(1,insultmaxidx)
                self.create_message(filekey, block=0, exitcode=0, insult=idx, substitue=0)
                return
        except KeyError,e:
            pass
        except IndexError,w:
            pass
        #Default action; allow-> out of memory
        self.create_message(filekey,block=0,exitcode=0,insult=0,substitue=0)

    def process_IN_CLOSE_WRITE(self, event):
        filename = os.path.join(event.path,event.name)
        msg = self.load_file(filename)
        #Send back a message
        self.decision(event.name,msg)
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


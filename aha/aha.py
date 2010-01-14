#!/usr/bin/python
#Core of the adaptive honeypot alternative
# (c) Gerard Wagener
#License GPL
import os,sys,random,getopt,ConfigParser
from pyinotify import *
from ctypes import *
from ahalib import *

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

def usage(exitcode):
    print """
Setup listener for kernel events of the user mode linux
    -h Shows this screen
    -c Specifies the config file

AUTHOR
    Gerard Wagener

LICENSE
    GPL
"""
    sys.exit(exitcode)
def shutdown(notifier):
    if notifier != None:
        print "Stop listening..."
        notifier.stop()

if __name__ == '__main__':
    notifier = None
    configfile = None
    try:
        opts,args = getopt.getopt(sys.argv[1:],"hc:",["help","config="])
        for o,a in opts:
            if o  in ('--help','-h'):
                usage(0)
            if o in ('--config','-c'):
                configfile = a

        if configfile == None:
            sys.stderr.write('A configuration file needs to be specified\n')
            sys.exit(1)
        #Load config file and get opts
        c=ConfigParser.ConfigParser()
        c.read(configfile)
        inqueue = c.get('common','inqueue')
        outqueue  = c.get('common','outqueue')
        insultmaxidx = int(c.get('insults','maxidx'))

        print "Setting up listeners..."
        wm = WatchManager()
        mask = IN_CLOSE_WRITE  # watched events

        notifier = Notifier(wm, KernelEvents(inqueue,outqueue,insultmaxidx))
        wdd = wm.add_watch(outqueue, mask, rec=True)

        print "Waiting for events..."
        while True:
            # process the queue of events as explained above
            notifier.process_events()
            if notifier.check_events():
                # read notified events and enqeue them
                notifier.read_events()
    except KeyboardInterrupt:
    # destroy the inotify's instance on this interrupt (stop monitoring)
        shutdown(notifier)
    except getopt.GetoptError,e:
        usage(1)
    except ConfigParser.NoOptionError,e:
        sys.stderr.write('Configuration error. (%s)\n'%(str(e)))
        sys.exit(1)
    sys.exit(0)

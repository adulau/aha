#!/usr/bin/python
#Core of the adaptive honeypot alternative
# (c) Gerard Wagener
#License GPL
import os,sys,random,getopt,ConfigParser
from pyinotify import *
from ctypes import *
from ahalib import *

class KernelEvents(ProcessEvent):

    def __init__(self,inqueue,outqueue,insultmaxidx,cases,block):
        self.ahaa = AHAActions(inqueue,outqueue)
        self.cases = cases
        self.block = block
        self.processtrees = ProcessTrees()

    #Blocks the sys_execve calls according the game
    def play(self):
        #By default allow the system call
        print "PLAY: mixed cases ",cases
        print "PLAY: blockpr", blockpr
        b = 0
        x = random.random()
         
        if x < self.cases:
            print "PLAY: Cases choice: ",x
            #i.e. in 0.54 blocking probability of 0.1 should be used
            y = random.random()
            print "PLAY: Blocking choice",y
            if y < self.block:
                b = 1
        else:
            # in the other cases another blocking probability should be used
            y = random.random()
            q = 1-self.block
            print "PLAY: Other blocking probability should be used ",q
            print "PLAY: Other blocking choice: ",y
            if y < q:
                b = 1
                
        return b

    def decision(self,filekey,msg):
        try:
            pid = int(msg['pid'][0])
            ppid = int(msg['ppid'][0])
            type = int(msg['type'][0])
            #Was a process closed?
            if type == 3:
                self.processtrees.silent_remove_pid(pid)
                return
            if type == 1:
                # Got sys_execve
                command = msg['file'][0]
                print "Got command: ",command, "in ",filekey
                #Is there a new SSH connection?
                if msg['file'][0] == '/usr/sbin/sshd':
                    print "New user found pid=",pid,",ppid=",ppid
                    self.processtrees.addUser(pid)
                    self.ahaa.create_message(filekey,block=0, exitcode=0,
                                             insult=0, substitue=0)
                    return

            #is this process induced by clone or sys_execve related to a user?
            if self.processtrees.searchTree(pid,ppid) == False:
                print "Process belongs to the system, allow it"
                #Note the process could also belong to a local
                #connected user
                self.ahaa.create_message(filekey,block=0, exitcode=0,
                                         insult=0, substitue=0)
                return
            else:
                print "Process belongs to a user, play"
                shouldBlock = self.play()
                if shouldBlock:
                    print "User process is artifically blocked ..."
                    self.ahaa.create_message(filekey,block=1, 
                                        exitcode=KERNEL_ERRORS.EACESS,insult=0,
                                        substitue=0)
                    return 
                else:
                    print "User process is allowed ..."
                    self.ahaa.create_message(filekey,block=0,exitcode=0,insult=0,
                                        substitue=0)
                    return
        except KeyError,e:
            print "EXCEPTION: KeyError"
        except IndexError,w:
            print "EXCEPTION: IndexError"
        except ValueError,s:
            print "EXCEPTION: ValueError"
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
        cases = float(c.get('game','cases'))
        blockpr = float(c.get('game','block'))

        print "Setting up listeners..."
        wm = WatchManager()
        mask = IN_CLOSE_WRITE  # watched events

        notifier = Notifier(wm, KernelEvents(inqueue,outqueue,insultmaxidx,
                            cases,blockpr))
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

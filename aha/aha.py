#!/usr/bin/python
#Core of the adaptive honeypot alternative
# (c) Gerard Wagener
#License GPL
import os,sys,random,getopt,ConfigParser
from pyinotify import *
from ctypes import *
from ahalib import *
import sys
import os
import sqlite3,os.path
class KernelEvents(ProcessEvent):

    def __init__(self,inqueue,outqueue,insultmaxidx, guidb):
        self.ahaa = AHAActions(inqueue,outqueue)
        self.database = guidb
        self.processtrees = ProcessTrees()
        if os.path.exists(self.database):
            self.con = sqlite3.connect(self.database)
            #Do it here to win time
            self.cur = self.con.cursor()
        else:
            os.system('pwd')
            print "[ERROR]  Database file not found  ",self.database
            sys.exit(1)

    def askgui(self, filekey,msg):
        ret = False
        program = os.path.basename(msg['file'][0])
        args = ','.join(msg['argument'][1:])
        #Lets see what the user has defined
        action = 0
        for row in  self.cur.execute('SELECT action FROM perms WHERE cmd=?',[program]):
            action = int(row[0])
        if action == 0:
            #Message is allowed
            self.ahaa.create_message(filekey,block=0,exitcode=0, insult=0,
                                     substitue=0)
            ret = True
        if action == 1:
            #Message is blocked
            self.ahaa.create_message(filekey, block=1,
                                     exitcode=KERNEL_ERRORS.EACESS, insult=0,
                                     substitue=0)
            ret = True
        if action == 2:
            #User is insulted
            self.ahaa.create_message(filekey, block=0, exitcode=0, insult=2,
                                     substitue=0)
            ret = True

        #Update the gui shell this takes time but the message had already
        #been transmitted to the kernel
        outstr = program + "(" + args + ")"
        self.cur.execute('INSERT INTO shell (cmd) VALUES (?)',[outstr])
        self.con.commit()
        #FIXME If fallback of decision to allow it is anyhow too late
        #Therefore allows the kernel by it self the execution
        return ret
        #Exception handling is done in decision method

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
                #Is there a new SSH connection?
                if msg['file'][0] == '/usr/sbin/sshd':
                    self.processtrees.addUser(pid)
                    self.ahaa.create_message(filekey,block=0, exitcode=0,
                                             insult=0, substitue=0)
                    #print "New user found pid=",pid,",ppid=",ppid
                    return

            #is this process induced by clone or sys_execve related to a user?
            if self.processtrees.searchTree(pid,ppid) == False:
                #Note the process could also belong to a local
                #connected user
                self.ahaa.create_message(filekey,block=0, exitcode=0,
                                         insult=0, substitue=0)
                #print "Process belongs to the system, allow it"
                return
            else:
                if msg.has_key('file'):
                    r = self.askgui(filekey,msg)
                    if r:
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
        guidb = c.get('gui','database')
        print "Setting up listeners..."
        wm = WatchManager()
        mask = IN_CLOSE_WRITE  # watched events

        k = KernelEvents(inqueue, outqueue,insultmaxidx,guidb)
        #If database is not valid exit here
        notifier = Notifier(wm,k)
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

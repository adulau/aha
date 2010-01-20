#Cleans up messages laying around from the kernel / aha framework
#Copyright (c) 2010 Gerard Wagener
#LICENSE GPL
#
#
#We assume that after the timeout the message must be consummed and then
#it is removed
#Do this as seperated process aiming to speed up at maximum time
#for the aha tak to take the decisions
#The aha framework can be launched then in screen
#
#TODO implement signal handler HUP flushes the file
import dircache,os.path,time,sys,ConfigParser,getopt, traceback
from ahalib import *

class PeriodTaks():
    #Define message types
    FROM_KERNEL  = 1
    TO_KERNEL    = 2
    
    def debug(self,msg):
        print "WDBG ",msg
    
    def __init__(self,outqueue,inqueue, timeout,sleeptime, logfile):
        self.outqueue= outqueue
        self.inqueue = inqueue
        self.timeout = timeout
        self.sleeptime = sleeptime
        self.logfile = logfile
        #Log file descriptor
        self.lfd = open(logfile,'a')
        self.aha = AHAActions(inqueue,outqueue)
        #Processtree related stuff
        self.ptree = ProcessTrees()

    #Make close action externally available
    def closeLogFile(self):
        self.lfd.close()

    def remove_old_msg(self,queue):
        msg = None
        #Get current date if the files are older than the timeout remove them
        t0 = int(time.strftime("%s"))
        files = dircache.listdir(queue)
        mlist = []
        for file in files:
            af = queue + os.sep + file
            #self.debug("found file : %s"%af)
            s = os.stat(af)
            t1 = int(s[os.path.stat.ST_CTIME])
            delta = t0 - t1
            if (delta > self.timeout):
                #self.debug("%s exceeds threshold"%af)
                #Old file was found record it
                if queue == self.outqueue:
                    msg = self.record_message(af,t1,PeriodTaks.FROM_KERNEL)
                    mlist.append(msg)
                if queue == self.inqueue:
                    msg = self.record_message(af,t1,PeriodTaks.TO_KERNEL)
                    mlist.append(msg)
                #Remove it
                self.aha.silent_clean(af)
        return mlist

    def clean_input_queue(self):
        try:
            self.remove_old_msg(self.inqueue)
        except OSError,e:
            exceptionType, exceptionValue, exceptionTraceback = sys.exc_info()
            traceback.print_exception(exceptionType, exceptionValue, 
                                     exceptionTraceback, file=sys.stderr)
            traceback.print_tb(exceptionTraceback, file=sys.stdout)

    

    def maintain_process_tree(self,mlist,exportFile):
        if mlist == None:
            return
        for msg in mlist:
            self.handle_msg(msg,exportFile)

    def handle_msg(self,msg,exportFile):
        try:
            if msg:
                type = int(msg['type'][0])
                pid = int(msg['pid'][0])
                ppid = int(msg['ppid'][0])
                #sys_execve messages
                if (type == 1):
                    self.debug('Got sys_execve message')
                    #Is there a new user
                    file = msg['file'][0]
                    self.debug('Got command:  %s, pid=%d,ppid=%d'%(file,pid,ppid))
                    self.ptree.annotateProcessList(msg)
                    if file == '/usr/sbin/sshd':
                        self.debug("New user found %s"%pid)
                        self.ptree.addUser(pid)
                    #Annotate all the processes
                #Check all pids and ppids
                if self.ptree.searchTree(pid,ppid):
                    self.debug("User related command %d"%pid)
                else:
                    self.debug("System related command")
                    #TODO free annotated list
                # Remove dead processes from process tree 
                if (type == 3):
                    pid = int(msg['pid'][0])
                    #When the attacker disconnects, regenerate a status file
                    if self.ptree.userList.has_key(pid):
                        print "User disconnected export file"
                        self.ptree.exportUserListTxt(exportFile)
                    #self.ptree.silent_remove_pid(pid)
        except KeyError,e:
            print e 
        except ValueError,e:
            print e
        except IndexError,e:
            print e
 
    def clean_output_queue(self):
        try:
            mlist = self.remove_old_msg(self.outqueue)
            #Propagate message list for further processor
            return mlist
        except OSError,e:
            exceptionType, exceptionValue, exceptionTraceback = sys.exc_info()
            traceback.print_exception(exceptionType, exceptionValue, 
                                     exceptionTraceback, file=sys.stderr)
            traceback.print_tb(exceptionTraceback, file=sys.stdout)

    #Parse the file an put the information in a log file for later processing
    #One log file is handier than for each message a file
    #Take timestamps when the kernel created the file
    def record_message(self,filename, ctime,type):
        try:
            if type == PeriodTaks.FROM_KERNEL:
                msg = self.aha.load_file(filename)
                logEntry = self.aha.serializeKernelMessage(msg,filename,ctime)
                self.lfd.write(logEntry)
                return msg

            if type == PeriodTaks.TO_KERNEL:
                msg = self.aha.get_kernel_reply(filename)
                logEntry=self.aha.serializeAhaReply(msg,filename,ctime)
                self.lfd.write(logEntry)
                return msg
        except IOError,e:
            sys.stderr.write('Failed to record message: %s\n'%filename)
        return mlist 

def usage(exitcode):
    print """
Do periodic tasks, like cleanups from the AHA framework

    -h Shows this screen
    -c Specifies the config file

AUTHOR

    Gerard Wagener

LICENSE

    GPL

"""
    return exitcode


configfile = None
isHelp = 0
p = None
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
    timeout = int(c.get('worker','timeout'))
    sleeptime = int(c.get('worker','sleeptime'))
    inqueue = c.get('common','inqueue')
    outqueue= c.get('common','outqueue')
    logfile = c.get('worker','logfile')
    userlistFile = c.get('worker','exportdir') + os.sep + 'userlist'
    
    p = PeriodTaks(outqueue, inqueue, timeout,sleeptime,logfile)
    print "Start working ..."

    while True:
        p.clean_input_queue()
        mlist = p.clean_output_queue()
        p.maintain_process_tree(mlist,userlistFile)
        time.sleep(sleeptime)
        print "Resume ..."

    sys.exit(0)
except getopt.GetoptError,e:
    usage(1)
except ConfigParser.NoOptionError,e:
    sys.stderr.write('Configuration error. (%s)\n'%(str(e)))
    sys.exit(1)
except KeyboardInterrupt,e:
    if p !=None:
        p.closeLogFile()
    sys.exit(0)
#Should not be reached
sys.exit(0)

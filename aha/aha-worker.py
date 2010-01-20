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


import dircache,os.path,time,sys,ConfigParser,getopt
from ahalib import *

class PeriodTaks():
    #Define message types
    FROM_KERNEL  = 1
    TO_KERNEL    = 2

    def __init__(self,outqueue,inqueue, timeout,sleeptime, logfile):
        self.outqueue= outqueue
        self.inqueue = inqueue
        self.timeout = timeout
        self.sleeptime = sleeptime
        self.logfile = logfile
        #Log file descriptor
        self.lfd = open(logfile,'a')
        self.aha = AHAActions(inqueue,outqueue)

    #Make close action externally available
    def closeLogFile(self):
        self.lfd.close()

    def remove_old_msg(self,queue):
        #Get current date if the files are older than the timeout remove them
        t0 = int(time.strftime("%s"))
        files = dircache.listdir(queue)
        for file in files:
            af = queue + os.sep + file
            s = os.stat(af)
            t1 = int(s[os.path.stat.ST_CTIME])
            delta = t0 - t1
            if (delta > self.timeout):
                #Old file was found record it
                if queue == self.outqueue:
                    self.record_message(af,t1,PeriodTaks.FROM_KERNEL)
                if queue == self.inqueue:
                    self.record_message(af,t1,PeriodTaks.TO_KERNEL)
                #Remove it
                self.aha.silent_clean(af)

    def clean_input_queue(self):
        try:
            self.remove_old_msg(self.inqueue)
        except OSError,e:
            sys.stderr.write(str(e))


    def clean_output_queue(self):
        try:
            self.remove_old_msg(self.outqueue)
        except OSError,e:
            sys.stderr.write(str(e))

    #Parse the file an put the information in a log file for later processing
    #One log file is handier than for each message a file
    #Take timestamps when the kernel created the file
    def record_message(self,filename, ctime,type):
        try:
            if type == PeriodTaks.FROM_KERNEL:
                msg = self.aha.load_file(filename)
                logEntry = self.aha.serializeKernelMessage(msg,filename,ctime)
                self.lfd.write(logEntry)

            if type == PeriodTaks.TO_KERNEL:
                msg = self.aha.get_kernel_reply(filename)
                logEntry=self.aha.serializeAhaReply(msg,filename,ctime)
                self.lfd.write(logEntry)
        except IOError,e:
            sys.stderr.write('Failed to record message: %s\n'%filename)

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
    p = PeriodTaks(outqueue, inqueue, timeout,sleeptime,logfile)
    print "Start working ..."
    while True:
        p.clean_input_queue()
        p.clean_output_queue()
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

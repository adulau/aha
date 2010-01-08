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

class PeriodTaks():

    def __init__(self,outqueue,inqueue, timeout,sleeptime):
        self.outqueue= outqueue
        self.inqueue = inqueue
        self.timeout = timeout
        self.sleeptime = sleeptime

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
                #Old file was found remove it
                os.unlink(af)


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

try:
    opts,args = getopt.getopt(sys.argv[1:],"hc:",["help","config="])
    for o,a in opts:
        if o  in ('--help','-h'):
            usage(0)
        if o in ('--config','-c'):
            configfile = a
    #Load config file and get opts
    c=ConfigParser.ConfigParser()
    c.read(configfile)
    timeout = int(c.get('worker','timeout'))
    sleeptime = int(c.get('worker','sleeptime'))
    inqueue = c.get('common','inqueue')
    outqueue= c.get('common','outqueue')
    p = PeriodTaks(outqueue, inqueue, timeout,sleeptime)
    print "Start working ..."
    while True:
        p.clean_input_queue()
        p.clean_output_queue()
        time.sleep(sleeptime)

    sys.exit(0)
except getopt.GetoptError,e:
    usage(1)
except TypeError,e:
    sys.stderr.write('Configuration file error\n')
except KeyboardInterrupt,e:
    sys.exit(0)
    sys.stderr.write(str(e))
    sys.exit(1)


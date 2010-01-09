#Common functions shared between aha and aha-worker
from ctypes import *
import os,sys,random,datetime,json,time

class AHAActions:

    def __init__(self,inqueue,outqueue):
        self.inqueue = inqueue
        self.outqueue = outqueue

    #Can trow IOError
    def load_file(self,filename):
        msg = {}
        fp = open(filename,'r')
        for i in fp.read().split('\n'):
            try:
                (key,value) = i.split('=')
                if msg.has_key(key) == False:
                    msg[key]=[]
                    msg[key].append(value)
            except ValueError,e:
                pass
        fp.close()
        return msg

    def silent_clean(self,filename):
        try:
            os.unlink(filename)
        except OSError,e:
            pass

    #Can trow IOError
    def create_message(self,filename,block,exitcode,substitue,insult):
        try:
            reply = ReplyMessage(block=block,exitcode=exitcode,substitue=substitue,
                                 insult = insult)
            fn = self.inqueue + os.sep + filename
            f = open (fn,'wb')
            f.write(reply)
            f.close()
            reply="(key=%s, block=%d,exitcode=%d,substitue=%d,insult=%d)"\
                   %(filename,block,exitcode, substitue,insult)
            return reply
        except IOError,e:
            sys.stderr.write('Could not create reply file=(%s)\n'%filename)
            #Propagate Error to higher level. Here it is only logged
            raise IOError(e)

    #Takes a parses kernel message as input and returns a serialized string
    #that can be put in a log file
    def serializeKernelMessage(self,msg,ctime):
        data = json.dumps(msg)
        obj=datetime.datetime.fromtimestamp(ctime)
        #FIXME aaargg timestamps are a mess in python
        #Use str() which is not portable, but I do not want to spend hours
        #of this shit
        sd = str(obj)
        return "%s|%s\n"%(sd,data);

    #Can throw IOError
    #FIXME not tested
    def get_kernel_reply(self,filename):
        fp = open(filename,'rb')
        buf = fp.read()
        fp.close()
        cstring = create_string_buffer(buf)
        rmsg = cast(pointer(cstring), POINTER(ReplyMessage)).contents
        return rmsg

    #FIXME not tested
    #Take a message read from get_kernel_reply function and return a string representation
    def serializeAhaReply(self,m,ctime):
        #Create generic hash. Structure may change
        msg= {'block':m.block,'exitcode':m.exitcode,'substitue':m.substitue,'insult':m.insult};
        #kernel message is also a generic hash table; reuse it
        return self.serializeKernelMessage(msg,ctime)

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



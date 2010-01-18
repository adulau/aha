#Common functions shared between aha and aha-worker
#FIXME Memory leak in process trees -> need to clean up them
#triggered by the kernel
from ctypes import *
import os,sys,random,datetime,json,time, unittest

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
    def serializeKernelMessage(self,msg,filename,ctime):
        data = json.dumps(msg)
        obj=datetime.datetime.fromtimestamp(ctime)
        fn = os.path.basename(filename)
        #FIXME aaargg timestamps are a mess in python
        #Use str() which is not portable, but I do not want to spend hours
        #of this shit
        sd = str(obj)
        return "%s|%s|%s\n"%(sd,fn,data);

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
    def serializeAhaReply(self,m,filename,ctime):
        #Create generic hash. Structure may change
        msg= {'block':m.block,'exitcode':m.exitcode,'substitue':m.substitue,'insult':m.insult};
        #kernel message is also a generic hash table; reuse it
        return self.serializeKernelMessage(msg,filename,ctime)

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

class ProcessTrees:
    def __init__(self):
        self.userList = {}
        self.processList = {}
        self.foundUser = 0

    def addUser(self,pid):
        self.userList[pid] = 1 #Shortcut to init

    def __searchTree(self, pid, ppid):
        #Always add it pid and ppid the list
        self.processList[pid] = ppid
        if self.userList.has_key(ppid):
            #print "DEBUG: user related command"
            self.foundUser = 1
            return
        #print "DEBUG: Searching ppid ",ppid, "in ",self.processList
        if self.processList.has_key(ppid):
            #print "DEBUG: found parent of ",pid, "which is ",ppid
            self.searchTree(ppid,self.processList[ppid])
        else:
            #print "DEBUG: Cannot find parent of ",ppid
            pass

    def searchTree(self,pid,ppid):
        #Make sure that pid is different from ppid -> to avoid recursion error
        self.foundUser = 0
        self.__searchTree(pid,ppid)
        #If the process belongs to the system remove it, to free up memory
        if self.foundUser == False:
            self.processList.pop(pid)
        return self.foundUser


class TestProcessTree(unittest.TestCase):
    def testSearchRegular0(self):
        x = ProcessTrees()
        x.addUser(1079)
        #self.assertDictEqual(x.userList, {1079:1})
        #FIXME python version is too old
        self.assertEqual(x.userList[1079],1)
        print "TEST: SSH clones a process 1081"
        ret = x.searchTree(1081,1079)
        self.assertEqual(ret,1)
        print "TEST: System itself adds a porcess 555"
        ret = x.searchTree(555,333)
        self.assertEqual(ret,0)
        print "TEST: User process 1081 creates a process 1082"
        ret = x.searchTree(1082,1081)
        self.assertEqual(ret,1)

        print "TEST: The clone clones again"
        ret = x.searchTree(1082,1081)
        self.assertEqual(ret,1)

        print "TEST: The system process 555 creates a process 888"
        ret = x.searchTree(888,555)
        self.assertEqual(ret,0)

        print "TEST: Second user arrives"
        x.addUser(2001)
        print "TEST: SSH clones a process"
        ret = x.searchTree(2002,2001)
        self.assertEqual(ret,1)
        print "TEST: Second user process create process 2007"
        ret=x.searchTree(2007,2002)
        self.assertEqual(ret,1)

        print "TEST: First user process 1081 executes uname ppid 1082"
        ret = x.searchTree(1082,1081)
        self.assertEqual(ret,1)

        print "TEST: Second user process 2007 creates process 2008"
        ret = x.searchTree(2008,2007)
        self.assertEqual(ret,1)

    def testCleanUp(self):
        x = ProcessTrees()
        #Init is executed
        ret = x.searchTree(1,0)
        self.assertEqual(ret,0)
        print x.processList
        self.assertEqual(len(x.processList.keys()),0)

    def testMixCleanUp(self):
        x = ProcessTrees()
        x.addUser(123)
        ret = x.searchTree(444,123)
        self.assertEqual(ret,1)
        self.assertEqual(len(x.processList.keys()),1)
        #System adds a process the process vector should not grow
        #Process 555 does not exits
        ret = x.searchTree(333,555)
        self.assertEqual(ret,0)
        self.assertEqual(len(x.processList.keys()),1)

if __name__ == '__main__':
    unittest.main()



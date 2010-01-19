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
        s = os.stat(filename)
        ts = int(s[os.path.stat.ST_CTIME])
        msg['timestamp'] = ts
        fp = open(filename,'r')
        for i in fp.read().split('\n'):
            try:
                (key,value) = i.split('=',1)
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
        self.aplist = {}
    #This first clone of /usr/sbin/sshd does not has the
    #SSH specific environment variables. Therefore ask all the
    #children
    def search_ssh_info(self,pid):
        print "Searching info for ",pid
        children = self.get_children(pid)
        print "Children of pid",children
        print type(children)
        for child in children:
            if self.aplist.has_key(child):
                print "Found annotations for child %d"%child
                if self.aplist[child].has_key('ssh_client'):
                    print "Found ssh info for child %d"%child
                    return self.aplist[child]['ssh_client']
        # Retuns None if ssh related information was not found
        sys.stderr.write('ERROR: No child provided SSH information\n')
        return None
        
    # Record additional information about processes like SSH parameters
    # and timestamps etc
    #TODO annotate SSH_LOGNAME
    #TODO annotate used terminal
    def annotateProcessList(self,msg):
        try:
            pid  = int(msg['pid'][0])
            ppid = int(msg['ppid'][0])
            if self.aplist.has_key(pid) == False:
                #Got a new process, so create a new dictionary for meta data
                self.aplist[pid] = dict()
            #Does the message  has a file name ?
            if msg.has_key('file'):
                self.aplist[pid]['file'] = msg['file'][0]
                print "Annotated pid=",pid, "file=",msg['file'][0]
            #Does the message has SSH related information?
            if msg.has_key('env'):
                # Go through the environment list
                for ev in msg['env']:
                    if ev.startswith('SSH_CLIENT='):
                        ev = ev.replace('SSH_CLIENT=','')
                        self.aplist[pid]['ssh_client'] = ev
                        print "Annotated pid=", pid," ev",ev
            # Is there a timestamp?
            if msg.has_key('timestamp'):
                self.aplist[pid]['timestamp'] = msg['timestamp']
 
        except ValueError,e:
            print e
            pass
        except IndexError,e:
            print e
            pass

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
        if pid == ppid:
            # Avoid recursion error
            return 0
        self.foundUser = 0
        self.__searchTree(pid,ppid)
        #If the process belongs to the system remove it, to free up memory
        if self.foundUser == False:
            self.processList.pop(pid)
        return self.foundUser

    #Recursively get the children of a process
    #Internal function
    def __get_children(self,pid):
        #Establish a list of children for a process
        children = []
        #FIXME not efficient; Go through all the processes
        for p in self.processList.keys():
            if  self.processList[p] == pid:
                children.append(p)
                #Record them in a global list too
                self.children[p]=1
        if len(children) == 0:
            return
        #Go through the children list and do a recursion
        for p in children:
            self.__get_children(p) 
        
    def get_children(self,pid):
        #Empty the list; do not want duplicates
        self.children = dict()
        self.__get_children(pid)
        return self.children.keys()

    def silent_remove_pid(self,pid):
        try:
            if self.processList.has_key(pid):
                self.processList.pop(pid)
            if self.userList.has_key(pid):
               self.userList.pop(pid)
               print "User in process ",pid," pid disconnected"
        except KeyError,e:
            pass

    def exportUserListTxt(self,filename):
        try:
            #Opens the file in append mode aiming to keep the history 
            f = open(filename, 'a')
            ts =  time.strftime("%Y-%m-%d %H:%M:%S") 
            f.write("*** UserList created on %s ***\n"%(str(ts)))
            for pid in self.userList.keys():
                print "Inspecting user: ",pid
                #See if some annotation is found for this pid
                if self.aplist.has_key(pid):
                    print "Found some annotations for",pid
                    #Look for SSH variables in the first child process
                    sshinfo = self.search_ssh_info(pid)
                    if sshinfo:
                        f.write("%s\n"%sshinfo)
                    else:
                        sys.stderr.write("No SSH information is there\n")
                    if self.aplist[pid].has_key('timestamp'):
                            #Convert timestamp
                            ts = self.aplist[pid]['timestamp']
                            obj=datetime.datetime.fromtimestamp(float(ts))
                            f.write("Connection date:%s\n\n"%str(obj))
                    else:
                        f.write("No timestamp information is there\n")
                else:
                    sys.stderr.write("No annotations found for pid: %d\n"%pid)
            f.close()
        except IOError,e:
            #TODO implement logging of internal errors
            #User should notice that there is something wrong when 
            #user lists are outdated or corrupted
            pass

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

    def testRecurionErrorBreak(self):
        #FIXME can an attacker create a process having its own parent?
        x  = ProcessTrees()
        x.addUser(123)
        x.searchTree(123,222)
        ret = x.searchTree(222,222)
        self.assertEqual(ret,0)

    def testAnnotate(self):
        msg = {'env': ['SHELL=/bin/sh', 'TERM=screen', 'SSH_CLIENT=192.168.1.23 49826 22', 'SSH_TTY=/dev/pts/0', 'USER=gabriela', 'MAIL=/var/mail/gabriela', 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games', 'PWD=/home/gabriela', 'LANG=en_US.UTF-8', 'HISTCONTROL=ignoreboth', 'SHLVL=1', 'HOME=/home/gabriela', 'LOGNAME=gabriela', 'SSH_CONNECTION=192.168.1.23 49826 192.168.1.1 22', '_=/usr/bin/lesspipe'], 'rppid': ['1138'], 'pid': ['1139'], 'argument': ['lesspipe'], 'DONE': ['1'], 'file': ['/usr/bin/lesspipe'], 'ppid': ['1138'], 'type': ['1'], 'timestamp':'1263846206'}
        x = ProcessTrees()
        x.annotateProcessList(msg)
        # Check if information is there
        self.assertEqual(x.aplist[1139]['timestamp'],'1263846206')
        s = "192.168.1.23 49826 22"
        self.assertEqual(x.aplist[1139]['ssh_client'],s)
        self.assertEqual(x.aplist[1139]['file'], '/usr/bin/lesspipe')
        x.addUser(1139)
        #Test export
        x.exportUserListTxt('/tmp/userlist.txt')

    def testChildrenList(self):
        x = ProcessTrees()
        x.addUser(123) # Has two children
        ret = x.searchTree(333,123)
        self.assertEqual(ret,1)

        ret = x.searchTree(334,123)
        self.assertEqual(ret,1)
        
        #First child has onother child
        ret = x.searchTree(555,333)
        self.assertEqual(ret,1)
        #Second child has another child
        ret = x.searchTree(666,334)
        self.assertEqual(ret,1)
        #Add concurrent user that has one child
        x.addUser(1000)
        ret = x.searchTree(1001,1000)
        self.assertEqual(ret,1)
        children = x.get_children(123)
        #[666, 555, 333, 334] 
        self.assertEqual(len(children), 4) 
        self.assertEqual(children[0],666)
        self.assertEqual(children[1],555)
        self.assertEqual(children[2],333)
        self.assertEqual(children[3],334)
        #Query children for an invalid process
        x= ProcessTrees()
        children = x.get_children(999)
        self.assertEqual(len(children),0)
    
if __name__ == '__main__':
    unittest.main()



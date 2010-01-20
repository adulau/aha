#!/usr/bin/python
#Analyse log files generated from aha-worker and generate reports
from ahalib import *
logfile='aha.log'
aha = AHAActions('../in','../out')
ptress = ProcessTrees()

def extract_object(obj):
    try:
        #FIXME Until now discard decisions from aha
        if obj.has_key('block') and obj.has_key('insult'):
            return 
        tp = int(obj['type'][0])
        pid = int(obj['pid'][0])
        ppid = int(obj['ppid'][0])
        ts = obj['timestamp']
        #handle sys_clone messages
        if (tp == 2):
            ptress.searchTree(pid,ppid)
            
        
        #handle sys_execve
        if (tp ==  1):
            file = obj['file'][0]
            if file == '/usr/sbin/sshd':
                print "Potential new user found: pid=",pid,"ppid=",ppid
                ptress.addUser(pid)
                ptress.annotateProcessList(obj) 
                return
            if ptress.searchTree(pid,ppid):
                print "User related command: ",file,"pid=",pid," ppid=",ppid
                #Annotation info is only available in sys_execve messages
                print "annotate process ",pid
                ptress.annotateProcessList(obj)                   
        #But need to record ppid for pid reusage .grrr
        if (tp == 2):
            if (ptress.searchTree(pid,ppid)):
                ptress.annotateProcessList(obj)
        # Thread exited
        if (tp == 3):
            if ptress.does_user_disconnects(pid):
                #User disconnected generate a report, to avoid that other 
                #information is droped
                print "List export is triggered for root ",pid
                ptress.exportUserListTxt('userlist.txt')
                ptress.silent_remove_pid(pid)
                #Cleanup annotated list
                print "Clean annotated list"
                ptress.clean_aplist(pid)
    except ValueError,e:
        print "Failed to parse ",obj
    except KeyError,e:
        print "Incomplete message"
 
line = None
try:
    f = open('aha.log','r')
    for line in f:
        (timestamp,key,serobj) = line.split('|',2)
        obj = aha.unserializeMessage(serobj)
        extract_object(obj)
    f.close()
except ValueError,e:
    #File may be incomplete
    print "Value error"
    print e
    print line

#Dump process trees
ptress.exportUserListTxt('userlist.txt')

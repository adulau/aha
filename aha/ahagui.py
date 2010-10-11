#!/usr/bin/python
#Adaptive Honeypot Demo
#Gerard Wagener
#License GPL

from PyQt4 import QtGui, QtCore
import getopt,sys,sqlite3

#Default values
commandList = ['uname', 'id','cat','wget','rm','ls','tar', 'vim']
database='gui.db'
shouldCreate = False
timerInterval = 500

def usage():
    print """
Adaptive Honeypot Alternative - Demo

ahagui [-hdc]

OPTIONS
    -h --help     Shows this screen
    -d --database Specify the message exchange database; default value = gui.db
    -c --create   Create a new database
"""

def createDatabase():
    try:

        con = sqlite3.connect(database)
        cur = con.cursor()
        cur.execute('CREATE TABLE perms (cmd VARCHAR(100), action INTEGER)')
        #Go through the command list and allow everything
        for command in commandList:
            cur.execute('INSERT INTO perms (cmd,action) VALUES (?,?)',
                        [command,0])
        cur.execute('CREATE TABLE shell (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, \
                     cmd VARCHAR(255))')
        con.commit()
        print "Database successfully created"

    except sqlite3.OperationalError,e:
        print e
        sys.stderr.write('Failed to create database '+database +'\n' )
        sys.exit(1)


def resetDatabase(con):
    cur=con.cursor()
    cur.execute('UPDATE perms SET action=0')
    cur.execute('DELETE FROM shell')
    con.commit()

class ActionCombo(QtGui.QComboBox):

    def __init__(self,name,con):
        QtGui.QComboBox.__init__(self)

        self.con = con
        self.actionList =  ['Allow','Block','Insult']
        self.addActions()
        self.name = name
        self.connect(self, QtCore.SIGNAL('currentIndexChanged (int)'),
                     QtCore.SLOT('handler(int)'))

    def addActions(self):
        for action in self.actionList:
            self.addItem(action)


    @QtCore.pyqtSlot('int')
    def handler(self,value):
        cur = self.con
        cur.execute('UPDATE perms SET action=? WHERE cmd=?',[value,self.name])
        con.commit()

class Example(QtGui.QWidget):


    def __init__(self, con):
        self.con = con
        QtGui.QWidget.__init__(self,None)

        self.initUI()
        self.lastId = 0

    @QtCore.pyqtSlot()
    def updateShell(self):
        try:
            cur = self.con.cursor()
            for row in cur.execute('SELECT cmd,id FROM shell WHERE id>?',
                               [self.lastId]):
                self.topright.appendPlainText(row[0])
                self.lastId = int(row[1])
        except sqlite3.OperationalError,e:
            self.topright.appendPlainText('Warning! System calls are not available')

    def initUI(self):

        hbox = QtGui.QHBoxLayout(self)

        topleft = QtGui.QWidget()
        topleftScroll = QtGui.QScrollArea()
        topleftgrid = QtGui.QGridLayout()
        topleft.setLayout(topleftgrid)

        self.topright = QtGui.QPlainTextEdit()

        #Scroll test
        for i in xrange(0,len(commandList)):
            name = commandList[i]
            topleftgrid.addWidget(QtGui.QLabel(name),i,0)
            topleftgrid.addWidget(ActionCombo(name,self.con),i,1)

        self.timer=QtCore.QTimer()
        QtCore.QObject.connect(self.timer, QtCore.SIGNAL("timeout()"),
                               self.updateShell)
        #FIXME Slot does work here?
        QtCore.QMetaObject.connectSlotsByName(self)
        self.timer.start(timerInterval)

        splitter1 = QtGui.QSplitter(QtCore.Qt.Horizontal)
        topleftScroll.setWidget(topleft)
        splitter1.addWidget(topleftScroll)
        splitter1.addWidget(self.topright)


        hbox.addWidget(splitter1)
        self.setLayout(hbox)

        self.setGeometry(250, 200, 450, 350)
        self.setWindowTitle('Adaptive Honeypot Alternative - Demo')


try:
    opts, args = getopt.getopt(sys.argv[1:], "hcd:", ["help", "create",
                               "database="])
    for o,a in opts:
        if o in ('-h','--help'):
            usage()
        if o in ('-d','--database'):
            database = a
        if o in ('-c','--create'):
            shouldCreate = True

except getopt.GetoptError, err:
        print str(err)
        usage()


if (shouldCreate):
    createDatabase()

con=None
try:
    con = sqlite3.connect(database)
    resetDatabase(con)

except sqlite3.OperationalError,e:
    sys.stderr.write('Cannot connect to message exchange database '
                     +database +'\n')
    sys.exit(1)

app = QtGui.QApplication([])
exm = Example(con)
exm.show()
app.exec_()


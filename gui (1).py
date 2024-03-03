from PyQt5.QtWidgets import *
from PyQt5.QtCore import Qt
import subprocess
import sys, csv
import qtmodern.styles
import qtmodern.windows


class Window(QWidget):
    def __init__(self):
        super().__init__()
        self.setGeometry(0,0,1500,1000)
        self.setWindowTitle("tcpdump network monitoring tool GUI")
        self.UI()

    def monitorModeMsg(self):
        QMessageBox.warning(self,"Warning","Put  the  interface  in monitor mode, this is supported only on IEEE 802.11 Wi-Fi interfaces, and supported only on some operatingsystems.\nNote that in monitor mode the adapter might disassociate from the network with which it's associated, so that you will not  be  ableto  use any wireless networks with that adapter.  This could prevent accessing files on a network server, or resolving host names ornetwork addresses, if you are capturing in monitor mode and are not connected to another network with another adapter.")

    def UI(self):
        self.mainLayout = QVBoxLayout()
        self.topLayout=QHBoxLayout()
        self.bottomLayout=QVBoxLayout()
        self.vbox1=QVBoxLayout()
        self.vbox2=QVBoxLayout()
        self.vbox3=QVBoxLayout()
        self.hbox=QHBoxLayout()
        self.hbox2=QHBoxLayout()

        self.interface=QComboBox()
        intList=self.getInterfaces()
        self.interface.addItems(intList)

        self.convertHost=QCheckBox("convert hosts")
        self.convertPort=QCheckBox("convert ports")
        self.monitorMode=QCheckBox("monitor mode")
        self.monitorMode.clicked.connect(self.monitorModeMsg)
        self.noPromiscuousMode=QCheckBox("no promiscuous mode")

        self.verboseLevel=QSlider(Qt.Horizontal)
        self.verboseLevel.setRange(0,3)
        # the app has some issues in displaying more detailed packet information, the verbose functionality is disabled
        self.verboseLevel.setDisabled(True)
        self.verboseLevel.setTickPosition(QSlider.TicksAbove)
        self.verboseLevel.setTickInterval(1)
        self.verboseLevel.valueChanged.connect(self.getValue)
        self.text=QLabel("verbose level : ")
        self.verbose=QLabel("0")

        self.scanButton=QPushButton("Scan")
        self.scanButton.clicked.connect(self.scan)
        self.stopButton=QPushButton("Stop")
        self.stopButton.clicked.connect(self.stop)
        self.stopButton.setDisabled(True)


        self.table=QTableWidget()
        self.table.setRowCount(0)
        self.table.setColumnCount(7)


        self.table.setHorizontalHeaderItem(0,QTableWidgetItem("Time"))
        self.table.setHorizontalHeaderItem(1,QTableWidgetItem("Protocol"))
        self.table.setHorizontalHeaderItem(2,QTableWidgetItem("source ip"))
        self.table.setHorizontalHeaderItem(3,QTableWidgetItem("source port"))
        self.table.setHorizontalHeaderItem(4,QTableWidgetItem("destination ip"))
        self.table.setHorizontalHeaderItem(5,QTableWidgetItem("destination port"))
        self.table.setHorizontalHeaderItem(6,QTableWidgetItem("other          "))
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.doubleClicked.connect(self.doubleClick)

        self.saveBtn=QPushButton("Save")
        self.saveBtn.clicked.connect(self.save)
        self.openBtn=QPushButton("Open")
        self.openBtn.clicked.connect(self.open)

        #self.darkBtn=QPushButton("dark")
        #self.darkBtn.clicked.connect(self.darkTheme)
        #self.lightBtn=QPushButton("light")
        #self.lightBtn.clicked.connect(self.lightTheme)

        #self.table.resizeColumnsToContents()
        #self.table.setItem(0,0,QTableWidgetItem("HhhhhhhhhhhhhhhhhhhhhhhhhhhhHH"))
        #self.table.horizontalHeader().hide()    # hide horizontal header
        #self.table.setSizeAdjustPolicy(QtWidgets.QAbstractScrollArea.AdjustToContents)
        #self.table.resizeColumnsToContents()

        #self.hbox2.addWidget(self.darkBtn)
        #self.hbox2.addWidget(self.lightBtn)
        self.hbox2.addStretch()
        self.hbox2.addWidget(self.saveBtn)
        self.hbox2.addWidget(self.openBtn)
        self.bottomLayout.addWidget(self.table)
        self.bottomLayout.addLayout(self.hbox2)

        self.topLayout.addWidget(self.interface)

        self.vbox1.addWidget(self.convertHost)
        self.vbox1.addWidget(self.convertPort)
        self.topLayout.addLayout(self.vbox1)

        self.vbox2.addWidget(self.monitorMode)
        self.vbox2.addWidget(self.noPromiscuousMode)
        self.topLayout.addLayout(self.vbox2)

        self.hbox.addWidget(self.text)
        self.hbox.addWidget(self.verbose)
        self.hbox.addStretch()
        self.vbox3.addLayout(self.hbox)
        self.vbox3.addWidget(self.verboseLevel)
        self.topLayout.addLayout(self.vbox3)

        self.topLayout.addStretch()
        self.topLayout.addWidget(self.scanButton)
        self.topLayout.addWidget(self.stopButton)

        self.mainLayout.addLayout(self.topLayout)
        self.mainLayout.addLayout(self.bottomLayout)

        self.setLayout(self.mainLayout)
        self.show()

    def getValue(self):
        val=self.verboseLevel.value()
        self.verbose.setText(str(val))

    def doubleClick(self):
        for item in self.table.selectedItems():
            QMessageBox.information(self,"Information",f"row number: {item.row()}\ncolumn number: {item.column()}\ncontent: {item.text()}")

    def scan(self):
        self.scanButton.setDisabled(True)
        self.saveBtn.setDisabled(True)
        self.openBtn.setDisabled(True)
        self.stopButton.setEnabled(True)
        self.table.setRowCount(0)

        cH=""
        cP=""
        mM=""
        nPM=""
        vL=""
        if self.convertHost.isChecked():
            cH="-n"
        if self.convertPort.isChecked():
            cP="-nn"
        if self.monitorMode.isChecked():
            mM="--monitor-mode"
        if self.noPromiscuousMode.isChecked():
            nPM="--no-promiscuous-mode"

        if self.verboseLevel.value() == 0:
            vL=""
        if self.verboseLevel.value() == 1:
            vL="-v"
        if self.verboseLevel.value() == 2:
            vL="-vv"
        if self.verboseLevel.value() == 3:
            vL="-vvv"

        i=str(self.interface.currentText())
        print(f"tcpdump -i {i} {cH} {cP} {mM} {nPM} {vL}")
        try:
            self.a = subprocess.Popen(f"tcpdump -i {i} {cH} {cP} {mM} {nPM} {vL} ",shell=True,stdout=subprocess.PIPE)
        except Exception as e:
            QMessageBox.critical(self, "ERROR", f"{e}")


    def stop(self):
        try:
            subprocess.run("killall tcpdump",shell=True)
        except Exception as e :
            QMessageBox.critical(self, "ERROR", f"{e}")
        else:
            self.capture()
            self.stopButton.setDisabled(True)
            self.scanButton.setEnabled(True)
            self.saveBtn.setEnabled(True)
            self.openBtn.setEnabled(True)


    def capture(self):
        self.listTable=[]
        self.listTable.append(['time','protocol','srcIp','srcPort','dstIp','dstPort','other'])
        a = self.a.communicate()[0]
        b = str(a.decode('utf-8'))
        l = b.split("\n")
        packetN=0
        for i in l:
            packetN=packetN+1
            print(i)
            k = i[10:].split(":",1)
            k[0]=i[:10]+k[0]
            o = k[0].split(" ")

            rowPosition=self.table.rowCount()

            try:
                w=str(o[2])
                ww = w[::-1].split(".",1)
                sportr=ww[0]
                sport=sportr[::-1]
                shostr=ww[1]
                shost=shostr[::-1]

                w2=str(o[4])
                ww2 = w2[::-1].split(".",1)
                dportr=ww2[0]
                dport=dportr[::-1]
                dhostr=ww2[1]
                dhost=dhostr[::-1]
            except Exception as e:
                QMessageBox.critical(self,"ERROR",f"error when compiling packer number {packetN}\n{e}")
                self.table.insertRow(rowPosition)
                continue
            else:
                self.table.insertRow(rowPosition)
                self.table.setItem(rowPosition, 0, QTableWidgetItem(o[0]))
                self.table.setItem(rowPosition, 1, QTableWidgetItem(o[1]))
                self.table.setItem(rowPosition, 2, QTableWidgetItem(shost))
                self.table.setItem(rowPosition, 3, QTableWidgetItem(sport))
                self.table.setItem(rowPosition, 4, QTableWidgetItem(dhost))
                self.table.setItem(rowPosition, 5, QTableWidgetItem(dport))
                self.table.setItem(rowPosition, 6, QTableWidgetItem(k[1]))
                self.listTable.append([o[0],o[1],shost,sport,dhost,dport,k[1]])


    def getInterfaces(self):
        intList = []
        intList2 = []
        try:
            int = subprocess.Popen("ip link show | awk {'print $2'} | grep :$",shell=True,stdout=subprocess.PIPE).communicate()[0]
        except Exception as e:
            err = QMessageBox.critical(self, "ERROR", f"{e}")
        else:
            int=str(int.decode('utf-8')).rstrip(":")
            intList=int.split('\n')
            for i in intList:
                j=i[:-1]
                intList2.append(j)
            return intList2


    def save(self):
        url=QFileDialog.getSaveFileName(self, "save a file", "", "CSV Files(*csv)")
        if url[0] != '':
            path=url[0]+".csv"
            with open(path, "w") as new_file:
                csv_writer = csv.writer(new_file, delimiter='~')
                for line in self.listTable:
                    csv_writer.writerow(line)
            QMessageBox.information(self,"Information",f"CSV file saved succesfully into this path {path}")

    def open(self):
        url = QFileDialog.getOpenFileName(self, "open a file", "", "CSV Files(*csv)")
        if url[0] != '':
            path=url[0]
            with open(path, "r") as file:
                csv_reader = csv.reader(file,delimiter='~')
                next(csv_reader)
                self.table.setRowCount(0)
                for line in csv_reader:
                    rowPosition = self.table.rowCount()
                    self.table.insertRow(rowPosition)
                    self.table.setItem(rowPosition, 0, QTableWidgetItem(line[0]))
                    self.table.setItem(rowPosition, 1, QTableWidgetItem(line[1]))
                    self.table.setItem(rowPosition, 2, QTableWidgetItem(line[2]))
                    self.table.setItem(rowPosition, 3, QTableWidgetItem(line[3]))
                    self.table.setItem(rowPosition, 4, QTableWidgetItem(line[4]))
                    self.table.setItem(rowPosition, 5, QTableWidgetItem(line[5]))
                    self.table.setItem(rowPosition, 6, QTableWidgetItem(line[6]))
            QMessageBox.information(self,"Information",f"CSV file exported succesfully from this path {path}")

    def darkTheme(self):
        self.close()
        w = Window()
        qtmodern.styles.dark(App)
        mw = qtmodern.windows.ModernWindow(w)
        mw.show()

    def lightTheme(self):
        self.close()
        w = Window()
        qtmodern.styles.light(App)
        mw = qtmodern.windows.ModernWindow(w)
        mw.show()



def main():
    global App
    global mw
    global w
    App = QApplication(sys.argv)
    w = Window()
    qtmodern.styles.dark(App)
    mw = qtmodern.windows.ModernWindow(w)
    mw.show()
    sys.exit(App.exec_())


if __name__ == '__main__':
    main()
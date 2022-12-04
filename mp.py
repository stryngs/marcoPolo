#!/usr/bin/python3

import argparse
from scapy.all import *

class Handler:
    __slots__ = ('args',
                 'bStr',
                 'dsDict',
                 'q')

    def __init__(self, args):
        self.args = args
        self.dsDict = {}

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

        ## Generate bitmap math
        bList = [b'\x00\x01\x00']
        self.bStr = bytes()
        for i in range(1):
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


    def snarf(self, q):
        """Our sniff function"""
        sniff(iface = self.args.m, prn = lambda x: q.put(x), store = 0)


    def sniffQueue(self):
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
                                    essid = self.dsDict.get(x.addr3)[0].decode()
                                    print('polo   -',
                                          x.addr3,
                                          essid,
                                          x.addr2, x.dBm_AntSignal)
                                # print(x.time)

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
                        essid = None
                        tbl = None
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
                        print('marco  -',
                              pkt.addr3, self.dsDict.get(pkt.addr3)[0].decode(),
                              pkt.dBm_AntSignal)
                        # print(pkt.time)

                        ### Hardcode cycle for polo
                        sendp(m, iface = self.args.i, count = 15,
                              inter = 3, verbose = False)
                        print(f'polo   - ~~~~~~~~~~~~~~~ > {self.dsDict.get(pkt.addr3)[0].decode()}')
        except Exception as E:
            print(E)


def main(hnd):
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
    args = parser.parse_args()
    hnd = Handler(args)

    ### Need to background this so we can query dsDict and fire on demand
    main(hnd)

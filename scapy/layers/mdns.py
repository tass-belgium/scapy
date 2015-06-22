## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
MDNS: Multicast DNS.
"""

import socket,struct

from scapy.packet import *
from scapy.fields import *
from scapy.ansmachine import *
from scapy.layers.inet import UDP

class MDNSStrField(StrField):

    def h2i(self, pkt, x):
      if x == "":
        return "."
      return x

    def i2m(self, pkt, x):
        if x == ".":
          return "\x00"

        x = [k[:63] for k in x.split(".")] # Truncate chunks that cannot be encoded (more than 63 bytes..)
        x = map(lambda y: chr(len(y))+y, x)
        x = "".join(x)
        if x[-1] != "\x00":
            x += "\x00"
        return x

    def getfield(self, pkt, s):
        n = ""

        if ord(s[0]) == 0:
          return s[1:], "."

        while 1:
            l = ord(s[0])
            s = s[1:]
            if not l:
                break
            if l & 0xc0:
                raise Scapy_Exception("MDNS message can't be compressed at this point!")
            else:
                n += s[:l]+"."
                s = s[l:]
        return s, n


class MDNSRRCountField(ShortField):
    holds_packets=1
    def __init__(self, name, default, rr):
        ShortField.__init__(self, name, default)
        self.rr = rr
    def _countRR(self, pkt):
        x = getattr(pkt,self.rr)
        i = 0
        while isinstance(x, MDNSRR) or isinstance(x, MDNSQR):
            x = x.payload
            i += 1
        return i
        
    def i2m(self, pkt, x):
        if x is None:
            x = self._countRR(pkt)
        return x
    def i2h(self, pkt, x):
        if x is None:
            x = self._countRR(pkt)
        return x
    

def MDNSgetstr(s,p):
    name = ""
    q = 0
    jpath = [p]
    while 1:
        if p >= len(s):
            warning("MDNS RR prematured end (ofs=%i, len=%i)"%(p,len(s)))
            break
        l = ord(s[p])
        p += 1
        if l & 0xc0:
            if not q:
                q = p+1
            if p >= len(s):
                warning("MDNS incomplete jump token at (ofs=%i)" % p)
                break
            p = ((l & 0x3f) << 8) + ord(s[p]) - 12
            if p in jpath:
                warning("MDNS decompression loop detected")
                break
            jpath.append(p)
            continue
        elif l > 0:
            name += s[p:p+l]+"."
            p += l
            continue
        break
    if q:
        p = q
    return name,p
        

class MDNSRRField(StrField):
    holds_packets=1
    def __init__(self, name, countfld, passon=1):
        StrField.__init__(self, name, None)
        self.countfld = countfld
        self.passon = passon
    def i2m(self, pkt, x):
        if x is None:
            return ""
        return str(x)
    def decodeRR(self, name, s, p):
        ret = s[p:p+10]
        type,cls,ttl,rdlen = struct.unpack("!HHIH", ret)
        p += 10
        rr = MDNSRR("\x00"+ret+s[p:p+rdlen])
        if rr.type in [2, 3, 4, 5]:
            rr.rdata = MDNSgetstr(s,p)[0]
        del(rr.rdlen)
        
        p += rdlen
        
        rr.rrname = name
        return rr,p
    def getfield(self, pkt, s):
        if type(s) is tuple :
            s,p = s
        else:
            p = 0
        ret = None
        c = getattr(pkt, self.countfld)
        if c > len(s):
            warning("wrong value: MDNS.%s=%i" % (self.countfld,c))
            return s,""
        while c:
            c -= 1
            name,p = MDNSgetstr(s,p)
            rr,p = self.decodeRR(name, s, p)
            if ret is None:
                ret = rr
            else:
                ret.add_payload(rr)
        if self.passon:
            return (s,p),ret
        else:
            return s[p:],ret
            
            
class MDNSQRField(MDNSRRField):
    holds_packets=1
    def decodeRR(self, name, s, p):
        ret = s[p:p+4]
        p += 4
        rr = MDNSQR("\x00"+ret)
        rr.qname = name
        return rr,p
        
        

class RDataField(StrLenField):
    def m2i(self, pkt, s):
        family = None
        if pkt.type == 1:
            family = socket.AF_INET
        elif pkt.type == 28:
            family = socket.AF_INET6
        elif pkt.type == 12:
            s = MDNSgetstr(s, 0)[0]
        if family is not None:    
            s = inet_ntop(family, s)
        return s
    def i2m(self, pkt, s):
        if pkt.type == 1:
            if s:
                s = inet_aton(s)
        elif pkt.type == 28:
            if s:
                s = inet_pton(socket.AF_INET6, s)
        elif pkt.type in [2,3,4,5]:
            s = "".join(map(lambda x: chr(len(x))+x, s.split(".")))
            if ord(s[-1]):
                s += "\x00"
        return s

class RDLenField(Field):
    def __init__(self, name):
        Field.__init__(self, name, None, "H")
    def i2m(self, pkt, x):
        if x is None:
            rdataf = pkt.get_field("rdata")
            x = len(rdataf.i2m(pkt, pkt.rdata))
        return x
    def i2h(self, pkt, x):
        if x is None:
            rdataf = pkt.get_field("rdata")
            x = len(rdataf.i2m(pkt, pkt.rdata))
        return x
    

class MDNS(Packet):
    name = "MDNS"
    fields_desc = [ ShortField("id",0),
                    BitField("qr",0, 1),
                    BitEnumField("opcode", 0, 4, {0:"QUERY",1:"IQUERY",2:"STATUS"}),
                    BitField("aa", 0, 1),
                    BitField("tc", 0, 1),
                    BitField("rd", 0, 1),
                    BitField("ra", 0 ,1),
                    BitField("z", 0, 1),
					BitField("ad", 0, 1),
					BitField("cd", 0, 1),
                    BitEnumField("rcode", 0, 4, {0:"ok", 1:"format-error", 2:"server-failure", 3:"name-error", 4:"not-implemented", 5:"refused"}),
                    MDNSRRCountField("qdcount", None, "qd"),
                    MDNSRRCountField("ancount", None, "an"),
                    MDNSRRCountField("nscount", None, "ns"),
                    MDNSRRCountField("arcount", None, "ar"),
                    MDNSQRField("qd", "qdcount"),
                    MDNSRRField("an", "ancount"),
                    MDNSRRField("ns", "nscount"),
                    MDNSRRField("ar", "arcount",0) ]
    def answers(self, other):
        return (isinstance(other, MDNS)
                and self.id == other.id
                and self.qr == 1
                and other.qr == 0)
        
    def mysummary(self):
        type = ["Qry","Ans"][self.qr]
        name = ""
        if self.qr:
            type = "Ans"
            if self.ancount > 0 and isinstance(self.an, MDNSRR):
                name = ' "%s"' % self.an.rdata
        else:
            type = "Qry"
            if self.qdcount > 0 and isinstance(self.qd, MDNSQR):
                name = ' "%s"' % self.qd.qname
        return 'MDNS %s%s ' % (type, name)

mdnstypes = { 0:"ANY", 255:"ALL",
             1:"A", 2:"NS", 3:"MD", 4:"MD", 5:"CNAME", 6:"SOA", 7: "MB", 8:"MG",
             9:"MR",10:"NULL",11:"WKS",12:"PTR",13:"HINFO",14:"MINFO",15:"MX",16:"TXT",
             17:"RP",18:"AFSDB",28:"AAAA", 33:"SRV",38:"A6",39:"DNAME"}

mdnsqtypes = {251:"IXFR",252:"AXFR",253:"MAILB",254:"MAILA",255:"ALL"}
mdnsqtypes.update(mdnstypes)
mdnsclasses =  {1: 'IN',  2: 'CS',  3: 'CH',  4: 'HS',  255: 'ANY'}


class MDNSQR(Packet):
    name = "MDNS Question Record"
    show_indent=0
    fields_desc = [ MDNSStrField("qname",""),
                    ShortEnumField("qtype", 1, mdnsqtypes),
                    BitField("uni", 0, 1),
                    BitField("useless", 0, 7),
                    ByteEnumField("qclass", 1, mdnsclasses) ]
                    
                    

class MDNSRR(Packet):
    name = "MDNS Resource Record"
    show_indent=0
    fields_desc = [ MDNSStrField("rrname",""),
                    ShortEnumField("type", 1, mdnstypes),
                    BitField("cache", 0, 1),
                    BitField("useless", 0, 7),
                    ByteEnumField("rclass", 1, mdnsclasses),
                    IntField("ttl", 0),
                    RDLenField("rdlen"),
                    RDataField("rdata", "", length_from=lambda pkt:pkt.rdlen) ]

bind_layers( UDP,           MDNS,           dport=5353)
bind_layers( UDP,           MDNS,           sport=5353)
bind_layers( MDNS,           MDNSRR)
bind_layers( MDNS,           MDNSQR)
# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
General utility functions.
"""


from decimal import Decimal

import collections
import decimal
import gzip
import os
import struct
import sys


from scapy.config import conf
from scapy.consts import WINDOWS
from scapy.data import MTU
from scapy.compat import orb
from scapy.error import Scapy_Exception, warning

# Typing imports
from scapy.compat import (
    Any,
    Dict,
    IO,
    List,
    Literal,
    Optional,
    TYPE_CHECKING,
    Tuple,
    Type,
    Union,
    overload,
)

if TYPE_CHECKING:
    from scapy.packet import Packet
    from scapy.plist import _PacketIterable, PacketList
    from scapy.supersocket import SuperSocket

_ByteStream = Union[IO[bytes], gzip.GzipFile]

###########
#  Tools  #
###########
class EDecimal(Decimal):
    """Extended Decimal

    This implements arithmetic and comparison with float for
    backward compatibility
    """

    def __add__(self, other, context=None):
        # type: (_Decimal, Any) -> EDecimal
        return EDecimal(Decimal.__add__(self, Decimal(other)))

    def __radd__(self, other):
        # type: (_Decimal) -> EDecimal
        return EDecimal(Decimal.__add__(self, Decimal(other)))

    def __sub__(self, other):
        # type: (_Decimal) -> EDecimal
        return EDecimal(Decimal.__sub__(self, Decimal(other)))

    def __rsub__(self, other):
        # type: (_Decimal) -> EDecimal
        return EDecimal(Decimal.__rsub__(self, Decimal(other)))

    def __mul__(self, other):
        # type: (_Decimal) -> EDecimal
        return EDecimal(Decimal.__mul__(self, Decimal(other)))

    def __rmul__(self, other):
        # type: (_Decimal) -> EDecimal
        return EDecimal(Decimal.__mul__(self, Decimal(other)))

    def __truediv__(self, other):
        # type: (_Decimal) -> EDecimal
        return EDecimal(Decimal.__truediv__(self, Decimal(other)))

    def __floordiv__(self, other):
        # type: (_Decimal) -> EDecimal
        return EDecimal(Decimal.__floordiv__(self, Decimal(other)))

    if sys.version_info >= (3,):
        def __divmod__(self, other):
            # type: (_Decimal) -> Tuple[EDecimal, EDecimal]
            r = Decimal.__divmod__(self, Decimal(other))
            return EDecimal(r[0]), EDecimal(r[1])
    else:
        def __div__(self, other):
            # type: (_Decimal) -> EDecimal
            return EDecimal(Decimal.__div__(self, Decimal(other)))

        def __rdiv__(self, other):
            # type: (_Decimal) -> EDecimal
            return EDecimal(Decimal.__rdiv__(self, Decimal(other)))

    def __mod__(self, other):
        # type: (_Decimal) -> EDecimal
        return EDecimal(Decimal.__mod__(self, Decimal(other)))

    def __rmod__(self, other):
        # type: (_Decimal) -> EDecimal
        return EDecimal(Decimal.__rmod__(self, Decimal(other)))

    def __pow__(self, other, modulo=None):
        # type: (_Decimal, Optional[_Decimal]) -> EDecimal
        return EDecimal(Decimal.__pow__(self, Decimal(other), modulo))

    def __eq__(self, other):
        # type: (Any) -> bool
        return super(EDecimal, self).__eq__(other) or float(self) == other

    def normalize(self, precision):  # type: ignore
        # type: (int) -> EDecimal
        with decimal.localcontext() as ctx:
            ctx.prec = precision
            return EDecimal(super(EDecimal, self).normalize(ctx))

class PcapReader_metaclass(type):
    """Metaclass for (Raw)Pcap(Ng)Readers"""

    def __new__(cls, name, bases, dct):
        # type: (Any, str, Any, Dict[str, Any]) -> Any
        """The `alternative` class attribute is declared in the PcapNg
        variant, and set here to the Pcap variant.

        """
        newcls = super(PcapReader_metaclass, cls).__new__(
            cls, name, bases, dct
        )
        if 'alternative' in dct:
            dct['alternative'].alternative = newcls
        return newcls

    def __call__(cls, filename, pcap_file):
        # type: (Union[IO[bytes], str], _ByteStream) -> Any
        """Creates a cls instance, use the `alternative` if that
        fails.

        """
        i = cls.__new__(
            cls,
            cls.__name__,
            cls.__bases__,
            cls.__dict__  # type: ignore
        )
        filename, pcap_file, fdesc, magic = cls.open(pcap_file)
        if not magic:
            raise Scapy_Exception(
                "No data could be read!"
            )
        try:
            i.__init__(filename, pcap_file, fdesc, magic)
            return i
        except (Scapy_Exception, EOFError):
            pass

        if "alternative" in cls.__dict__:
            cls = cls.__dict__["alternative"]
            i = cls.__new__(
                cls,
                cls.__name__,
                cls.__bases__,
                cls.__dict__  # type: ignore
            )
            try:
                i.__init__(filename, pcap_file, fdesc, magic)
                return i
            except (Scapy_Exception, EOFError):
                pass

        raise Scapy_Exception("Not a supported capture file")

    @staticmethod
    def open_old(fname  # type: Union[IO[bytes], str]
             ):
        # type: (...) -> Tuple[str, _ByteStream, bytes]
        """Open (if necessary) filename, and read the magic."""
        if isinstance(fname, str):
            filename = fname
            try:
                fdesc = gzip.open(filename, "rb")  # type: _ByteStream
                magic = fdesc.read(4)
            except IOError:
                fdesc = open(filename, "rb")
                magic = fdesc.read(4)
        else:
            fdesc = fname
            filename = getattr(fdesc, "name", "No name")
            magic = fdesc.read(4)
        return filename, fdesc, magic

    def open(fname, pcap_file):
        # type: (...) -> Tuple[str, _ByteStream, bytes]
        fdesc = pcap_file
        filename = "pcap_file"
        print(pcap_file)
        magic = pcap_file.read(4)
        return filename, pcap_file, fdesc, magic

class RawPcapReader(metaclass=PcapReader_metaclass):
    """A stateful pcap reader. Each packet is returned as a string"""

    # TODO: use Generics to properly type the various readers.
    # As of right now, RawPcapReader is typed as if it returned packets
    # because all of its child do. Fix that

    nonblocking_socket = True
    PacketMetadata = collections.namedtuple("PacketMetadata",
                                            ["sec", "usec", "wirelen", "caplen"])  # noqa: E501

    def __init__(self, filename, pcap_file, fdesc=None, magic=None):  # type: ignore
        # type: (str, _ByteStream, _ByteStream, bytes) -> None
        self.filename = filename
        self.f = fdesc
        if magic == b"\xa1\xb2\xc3\xd4":  # big endian
            self.endian = ">"
            self.nano = False
        elif magic == b"\xd4\xc3\xb2\xa1":  # little endian
            self.endian = "<"
            self.nano = False
        elif magic == b"\xa1\xb2\x3c\x4d":  # big endian, nanosecond-precision
            self.endian = ">"
            self.nano = True
        elif magic == b"\x4d\x3c\xb2\xa1":  # little endian, nanosecond-precision  # noqa: E501
            self.endian = "<"
            self.nano = True
        else:
            raise Scapy_Exception(
                "Not a pcap capture file (bad magic: %r)" % magic
            )
        hdr = self.f.read(20)
        if len(hdr) < 20:
            raise Scapy_Exception("Invalid pcap file (too short)")
        vermaj, vermin, tz, sig, snaplen, linktype = struct.unpack(
            self.endian + "HHIIII", hdr
        )
        self.linktype = linktype
        self.snaplen = snaplen

    def __enter__(self):
        # type: () -> RawPcapReader
        return self

    def __iter__(self):
        # type: () -> RawPcapReader
        return self

    def __next__(self):
        # type: () -> Tuple[bytes, RawPcapReader.PacketMetadata]
        """
        implement the iterator protocol on a set of packets in a pcap file
        """
        try:
            return self._read_packet()
        except EOFError:
            raise StopIteration

    def _read_packet(self, size=MTU):
        # type: (int) -> Tuple[bytes, RawPcapReader.PacketMetadata]
        """return a single packet read from the file as a tuple containing
        (pkt_data, pkt_metadata)

        raise EOFError when no more packets are available
        """
        hdr = self.f.read(16)
        if len(hdr) < 16:
            raise EOFError
        sec, usec, caplen, wirelen = struct.unpack(self.endian + "IIII", hdr)
        return (self.f.read(caplen)[:size],
                RawPcapReader.PacketMetadata(sec=sec, usec=usec,
                                             wirelen=wirelen, caplen=caplen))

    def read_packet(self, size=MTU):
        # type: (int) -> Packet
        raise Exception(
            "Cannot call read_packet() in RawPcapReader. Use "
            "_read_packet()"
        )

    def dispatch(self,
                 callback):
        # type: (...) -> None
        """call the specified callback routine for each packet read

        This is just a convenience function for the main loop
        that allows for easy launching of packet processing in a
        thread.
        """
        for p in self:
            callback(p)

    def _read_all(self, count=-1):
        # type: (int) -> List[Packet]
        """return a list of all packets in the pcap file
        """
        res = []  # type: List[Packet]
        while count != 0:
            count -= 1
            try:
                p = self.read_packet()  # type: Packet
            except EOFError:
                break
            res.append(p)
        return res

    def recv(self, size=MTU):
        # type: (int) -> bytes
        """ Emulate a socket
        """
        return self._read_packet(size=size)[0]

    def fileno(self):
        # type: () -> int
        return -1 if WINDOWS else self.f.fileno()

    def close(self):
        # type: () -> Optional[Any]
        return self.f.close()

    def __exit__(self, exc_type, exc_value, tracback):
        # type: (Optional[Any], Optional[Any], Optional[Any]) -> None
        self.close()

    # emulate SuperSocket
    @staticmethod
    def select(sockets,  # type: List[SuperSocket]
               remain=None,  # type: Optional[float]
               ):
        # type: (...) -> List[SuperSocket]
        return sockets


class PcapReader(RawPcapReader):
    def __init__(self, filename, pcap_file, fdesc=None, magic=None):  # type: ignore
        # type: (str, IO[bytes], IO[bytes], bytes) -> None
        RawPcapReader.__init__(self, filename, pcap_file, fdesc, magic)
        try:
            self.LLcls = conf.l2types.num2layer[
                self.linktype
            ]  # type: Type[Packet]
        except KeyError:
            warning("PcapReader: unknown LL type [%i]/[%#x]. Using Raw packets" % (self.linktype, self.linktype))  # noqa: E501
            if conf.raw_layer is None:
                # conf.raw_layer is set on import
                import scapy.packet  # noqa: F401
            self.LLcls = conf.raw_layer

    def __enter__(self):
        # type: () -> PcapReader
        return self

    def read_packet(self, size=MTU):
        # type: (int) -> Packet
        rp = super(PcapReader, self)._read_packet(size=size)
        if rp is None:
            raise EOFError
        s, pkt_info = rp

        try:
            p = self.LLcls(s)  # type: Packet
        except KeyboardInterrupt:
            raise
        except Exception:
            if conf.debug_dissector:
                from scapy.sendrecv import debug
                debug.crashed_on = (self.LLcls, s)
                raise
            if conf.raw_layer is None:
                # conf.raw_layer is set on import
                import scapy.packet  # noqa: F401
            p = conf.raw_layer(s)
        power = Decimal(10) ** Decimal(-9 if self.nano else -6)
        p.time = EDecimal(pkt_info.sec + power * pkt_info.usec)
        p.wirelen = pkt_info.wirelen
        return p

    def recv(self, size=MTU):  # type: ignore
        # type: (int) -> Packet
        return self.read_packet(size=size)

    def __next__(self):  # type: ignore
        # type: () -> Packet
        try:
            return self.read_packet()
        except EOFError:
            raise StopIteration

    def read_all(self, count=-1):
        # type: (int) -> PacketList
        res = self._read_all(count)
        from scapy import plist
        return plist.PacketList(res, name=os.path.basename(self.filename))


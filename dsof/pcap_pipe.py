"""Bounded PCAP FIFO reader: tcpdump alone holds macOS capture privileges."""
import os
import select
import stat
import struct
import threading
import time
from .capture import Collector

class PipeCollector(Collector):
    def __init__(self, path, interfaces, callback, excluded_ports, queue_size):
        super().__init__(interfaces, callback, excluded_ports, queue_size)
        self.path = path
        self._reader = None
        self._status['backend'] = 'tcpdump_fifo'
        self._status['pipe'] = str(path)

    def start(self):
        if self._reader and self._reader.is_alive():
            return self.status()
        try:
            info = self.path.lstat()
            if not stat.S_ISFIFO(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise ValueError('Capture path must be a private FIFO owned by the current user')
        except Exception as exc:
            self._fail(f'{exc}. Run sh tools/prepare_capture.sh first.')
            return self.status()
        self._stopping.clear()
        with self._lock:
            self._status.update(state='waiting_for_sensor',ready=False,last_error=None)
        self._worker = threading.Thread(target=self._consume,daemon=True,name='dsof-pipe-consumer')
        self._reader = threading.Thread(target=self._read,daemon=True,name='dsof-pcap-reader')
        self._worker.start()
        self._reader.start()
        return self.status()

    def _read(self):
        from scapy.all import conf
        fd = os.open(self.path,os.O_RDONLY|os.O_NONBLOCK)
        buffer = bytearray()
        endian = decoder = None
        divisor = 1_000_000
        seen_writer = False
        try:
            while not self._stopping.is_set():
                readable,_,_ = select.select([fd],[],[],.2)
                if not readable:
                    continue
                chunk = os.read(fd,65536)
                if not chunk:
                    if seen_writer:
                        with self._lock:
                            self._status.update(state='waiting_for_sensor',ready=False,last_error='Capture helper disconnected')
                        buffer.clear()
                        endian = decoder = None
                        seen_writer = False
                    self._stopping.wait(.1)
                    continue
                seen_writer = True
                buffer.extend(chunk)
                if endian is None:
                    if len(buffer) < 24:
                        continue
                    formats = {b'\xd4\xc3\xb2\xa1':('<',1_000_000), b'\xa1\xb2\xc3\xd4':('>',1_000_000),
                               b'\x4d\x3c\xb2\xa1':('<',1_000_000_000), b'\xa1\xb2\x3c\x4d':('>',1_000_000_000)}
                    if bytes(buffer[:4]) not in formats:
                        raise ValueError('Expected classic PCAP from tcpdump -w -')
                    endian, divisor = formats[bytes(buffer[:4])]
                    major, minor, _, _, snaplen, link = struct.unpack(endian+'HHIIII',buffer[4:24])
                    if (major,minor)!=(2,4) or not 1 <= snaplen <= 262144:
                        raise ValueError('Unsupported PCAP header')
                    decoder = conf.l2types.get(link)
                    if decoder is None:
                        raise ValueError(f'Unsupported link type {link}')
                    del buffer[:24]
                    with self._lock:
                        self._status.update(state='running',ready=True,last_error=None,opened_interfaces=self.interfaces,ready_since=time.time())
                while len(buffer) >= 16:
                    seconds, fraction, captured, original = struct.unpack(endian+'IIII',buffer[:16])
                    if captured > 262144 or original < captured or fraction >= divisor:
                        raise ValueError('Invalid PCAP packet length or timestamp')
                    if len(buffer) < 16+captured:
                        break
                    if captured == original:
                        raw = decoder(bytes(buffer[16:16+captured]))
                        raw.time = seconds + fraction/divisor
                        raw.sniffed_on = self.interfaces[0]
                        self._on_raw(raw)
                    else:
                        with self._lock:
                            self._status['unsupported_packets'] += 1
                    del buffer[:16+captured]
        except Exception as exc:
            self._fail(f'PCAP helper failed: {exc}')
        finally:
            os.close(fd)

    def stop(self):
        result = super().stop()
        if self._reader and self._reader is not threading.current_thread():
            self._reader.join(timeout=2)
        return result

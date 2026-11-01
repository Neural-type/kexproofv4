import re


class RSPClient:
    def __init__(self, pid, host="127.0.0.1", port=12345):
        import socket
        self.sock = socket.create_connection((host, port), timeout=10)
        self.buffer = b""
        self.thread_id = None
        self.sock.sendall(b"+")
        self.call("qSupported")
        attached = self.call(f"vAttach;{pid:x}", timeout=60)
        if attached.startswith(b"E") or not attached:
            raise RuntimeError(f"attach failed: {attached!r}")
        thread = re.search(rb"thread:([0-9a-fA-F]+)", attached)
        if thread:
            self.thread_id = thread.group(1).decode()
        print(f"ATTACH_OK pid={pid}", flush=True)

    def recv(self, timeout=10):
        self.sock.settimeout(timeout)
        while True:
            start = self.buffer.find(b"$")
            if start >= 0:
                end = self.buffer.find(b"#", start)
                if end >= 0 and len(self.buffer) >= end + 3:
                    packet = self.buffer[start + 1:end]
                    self.buffer = self.buffer[end + 3:]
                    return packet
            chunk = self.sock.recv(65536)
            if not chunk:
                raise EOFError("RSP closed")
            self.buffer += chunk

    def call(self, command, timeout=10, verbose=True):
        data = command.encode()
        self.sock.sendall(b"$" + data + b"#" + f"{sum(data) & 0xff:02x}".encode())
        response = self.recv(timeout)
        self.sock.sendall(b"+")
        if verbose:
            rendered = response.decode("utf-8", "backslashreplace")
            if len(rendered) > 2000:
                rendered = rendered[:2000] + f"... <{len(response)} bytes>"
            print(f"{command} => {rendered}", flush=True)
        return response

    def continue_and_wait(self, timeout=120):
        self.sock.sendall(b"$c#63")
        response = self.recv(timeout)
        self.sock.sendall(b"+")
        self._remember_thread(response)
        print(f"c => {response.decode('utf-8', 'backslashreplace')}", flush=True)
        return response

    def step_and_wait(self, timeout=15):
        self.sock.sendall(b"$s#73")
        response = self.recv(timeout)
        self.sock.sendall(b"+")
        self._remember_thread(response)
        print(f"s => {response.decode('utf-8', 'backslashreplace')}", flush=True)
        return response

    def _remember_thread(self, response):
        thread = re.search(rb"thread:([0-9a-fA-F]+)", response)
        if thread:
            self.thread_id = thread.group(1).decode()

    def registers(self, indices=(0, 20, 23, 29, 31, 32)):
        if self.thread_id:
            self.call(f"Hg{self.thread_id}", verbose=False)
        values = {}
        for index in indices:
            raw = self.call(f"p{index:x}", verbose=False)
            data = bytes.fromhex(raw.decode())
            if not data:
                raise RuntimeError(f"empty register p{index:x}")
            values[index] = int.from_bytes(data, "little")
        print("REGISTERS " + " ".join(f"x{index}=0x{value:x}" for index, value in values.items()), flush=True)
        return values

    def memory(self, address, size):
        response = self.call(f"m{address:x},{size:x}", verbose=False)
        try:
            data = bytes.fromhex(response.decode())
        except ValueError:
            raise RuntimeError(f"memory read failed: {response!r}")
        print(f"MEMORY 0x{address:x}..0x{address + size:x}: {data.hex(' ', 1)}", flush=True)
        return data

    def u64(self, address):
        return int.from_bytes(self.memory(address, 8), "little")

    def set_breakpoint(self, address, kind=0, size=4):
        response = self.call(f"Z{kind},{address:x},{size:x}")
        if response != b"OK":
            raise RuntimeError(f"breakpoint failed: {response!r}")

    def clear_breakpoint(self, address, kind=0, size=4):
        response = self.call(f"z{kind},{address:x},{size:x}")
        if response != b"OK":
            raise RuntimeError(f"breakpoint removal failed: {response!r}")

    def detach(self):
        try:
            print("DETACH", self.call("D"), flush=True)
        finally:
            self.sock.close()

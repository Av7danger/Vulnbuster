import asyncio
import frida
from typing import Dict, Any, List
import json
from pathlib import Path

# --- Frida Dynamic Analysis Runner ---
class FridaRunner:
    def __init__(self, target_package: str, device_id: str = None):
        self.target_package = target_package
        self.device_id = device_id
        self.session = None
        self.script = None
        
    async def connect_device(self) -> bool:
        """Connect to Android device/emulator"""
        try:
            if self.device_id:
                self.device = frida.get_device(self.device_id)
            else:
                self.device = frida.get_usb_device()
            return True
        except Exception as e:
            print(f"[Frida] Device connection failed: {e}")
            return False
    
    async def attach_to_app(self) -> bool:
        """Attach to running app or spawn new process"""
        try:
            self.session = await self.device.attach(self.target_package)
            return True
        except Exception as e:
            try:
                # Try spawning if attach fails
                self.session = await self.device.spawn([self.target_package])
                await self.device.resume(self.session.pid)
                return True
            except Exception as e2:
                print(f"[Frida] App attachment failed: {e2}")
                return False
    
    async def inject_hooks(self) -> str:
        """Inject JavaScript hooks for dynamic analysis"""
        hook_script = """
        // Memory string extraction
        var strings = [];
        var syscalls = [];
        
        // Hook string operations
        Interceptor.attach(Module.findExportByName("libc.so", "strcpy"), {
            onEnter: function(args) {
                var str = Memory.readUtf8String(args[1]);
                if (str && str.length > 3) {
                    strings.push(str);
                }
            }
        });
        
        // Hook network calls
        Interceptor.attach(Module.findExportByName("libc.so", "connect"), {
            onEnter: function(args) {
                var sockaddr = args[1];
                var addr = Memory.readPointer(sockaddr.add(4));
                var port = Memory.readU16(sockaddr.add(2));
                syscalls.push("connect:" + addr + ":" + port);
            }
        });
        
        // Hook file operations
        Interceptor.attach(Module.findExportByName("libc.so", "open"), {
            onEnter: function(args) {
                var path = Memory.readUtf8String(args[0]);
                if (path) {
                    syscalls.push("open:" + path);
                }
            }
        });
        
        // Send data back to Python
        setInterval(function() {
            send({
                type: "strings",
                data: strings.splice(0, strings.length)
            });
            send({
                type: "syscalls", 
                data: syscalls.splice(0, syscalls.length)
            });
        }, 1000);
        """
        
        try:
            self.script = await self.session.create_script(hook_script)
            self.script.message.connect(self._on_message)
            await self.script.load()
            return "Hooks injected successfully"
        except Exception as e:
            return f"Hook injection failed: {e}"
    
    def _on_message(self, message, data):
        """Handle messages from Frida hooks"""
        if message['type'] == 'send':
            payload = message['payload']
            if payload['type'] == 'strings':
                self._save_strings(payload['data'])
            elif payload['type'] == 'syscalls':
                self._save_syscalls(payload['data'])
    
    def _save_strings(self, strings: List[str]):
        """Save extracted strings to log file"""
        log_path = Path('dynamic/logs/strings.json')
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, 'a') as f:
            json.dump({'strings': strings, 'timestamp': asyncio.get_event_loop().time()}, f)
            f.write('\n')
    
    def _save_syscalls(self, syscalls: List[str]):
        """Save syscall logs"""
        log_path = Path('dynamic/logs/syscalls.json')
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, 'a') as f:
            json.dump({'syscalls': syscalls, 'timestamp': asyncio.get_event_loop().time()}, f)
            f.write('\n')
    
    async def run_dynamic_analysis(self, duration: int = 60) -> Dict[str, Any]:
        """Run complete dynamic analysis session"""
        if not await self.connect_device():
            return {'error': 'Device connection failed'}
        
        if not await self.attach_to_app():
            return {'error': 'App attachment failed'}
        
        hook_result = await self.inject_hooks()
        
        # Run for specified duration
        await asyncio.sleep(duration)
        
        return {
            'status': 'completed',
            'hook_result': hook_result,
            'duration': duration,
            'logs': {
                'strings': 'dynamic/logs/strings.json',
                'syscalls': 'dynamic/logs/syscalls.json'
            }
        } 
"""
Frida Script Manager for Dynamic Analysis.

This module provides a centralized way to manage and execute Frida scripts
for dynamic analysis of mobile applications.
"""
import asyncio
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable, Coroutine

import frida
from frida.core import Device as FridaDevice, Script as FridaScript

logger = logging.getLogger(__name__)

class FridaScriptManager:
    """Manager for Frida scripts and device communication."""
    
    # Built-in Frida scripts
    BUILTIN_SCRIPTS = {
        'android_ssl_pinning_bypass': """
        // Android SSL Pinning Bypass
        // Bypasses common SSL pinning implementations
        
        console.log('[*] Starting SSL Pinning Bypass Script');
        
        // Common SSL pinning bypass for various libraries
        const sslPinningBypass = {
            // Bypass for OkHttp
            okhttp: function() {
                const OkHttpClient = Java.use('okhttp3.OkHttpClient');
                const Builder = OkHttpClient.Builder;
                
                // Bypass certificate pinning in OkHttp
                Builder.build.implementation = function() {
                    console.log('[*] Bypassing OkHttp certificate pinning');
                    // Disable certificate pinning
                    this.sslSocketFactory(null, null);
                    this.hostnameVerifier(Java.use('javax.net.ssl.HostnameVerifier').$new({
                        verify: function(hostname, session) {
                            return true;
                        }
                    }));
                    return this.build();
                };
            },
            
            // Bypass for Android's WebViewClient
            webview: function() {
                const WebViewClient = Java.use('android.webkit.WebViewClient');
                
                // Override onReceivedSslError
                WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
                    console.log('[*] Bypassing WebView SSL error: ' + error);
                    handler.proceed();
                };
                
                // Override onReceivedHttpAuthRequest
                WebViewClient.onReceivedHttpAuthRequest.implementation = function(view, handler, host, realm) {
                    console.log('[*] Bypassing HTTP auth request');
                    handler.proceed('user', 'pass');
                };
            },
            
            // Bypass for TrustManager
            trustmanager: function() {
                const TrustManager = Java.use('javax.net.ssl.TrustManager');
                const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
                
                // Create a custom TrustManager that trusts all certificates
                const TrustManagers = [Java.registerClass({
                    name: 'com.example.TrustAllCerts',
                    implements: [X509TrustManager],
                    methods: {
                        checkClientTrusted: function(chain, authType) {
                            console.log('[*] Bypassing client certificate check');
                        },
                        checkServerTrusted: function(chain, authType) {
                            console.log('[*] Bypassing server certificate check');
                        },
                        getAcceptedIssuers: function() {
                            return [];
                        }
                    }
                }).$new()];
                
                // Override the default TrustManager
                const SSLContext = Java.use('javax.net.ssl.SSLContext');
                SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(km, tm, sr) {
                    console.log('[*] Overriding SSLContext.init()');
                    return this.init(km, TrustManagers, sr);
                };
            },
            
            // Bypass for Android N (API 24+) Network Security Configuration
            networkSecurityConfig: function() {
                const NetworkSecurityConfig = Java.use('android.security.net.config.NetworkSecurityConfig');
                const ApplicationInfo = Java.use('android.content.pm.ApplicationInfo');
                
                // Bypass network security config
                NetworkSecurityConfig.$init.overload('boolean', 'boolean', 'int', 'java.util.Set', 'java.util.Set', 'int', 'int').implementation = function(
                    cleartextTrafficPermitted, 
                    hstsEnforced, 
                    pinSetFuture, 
                    pinSet, 
                    unpins, 
                    certsRefs, 
                    certsArraySize
                ) {
                    console.log('[*] Bypassing Network Security Config');
                    return this.$init(true, false, pinSetFuture, null, null, 0, 0);
                };
            },
            
            // Bypass for CertificatePinner in OkHttp
            certificatePinner: function() {
                const CertificatePinner = Java.use('okhttp3.CertificatePinner');
                
                // Override check method
                CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
                    console.log('[*] Bypassing CertificatePinner.check() for: ' + hostname);
                    return;
                };
                
                // Override check$okhttp method (used in newer versions)
                CertificatePinner.check$okhttp.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
                    console.log('[*] Bypassing CertificatePinner.check$okhttp() for: ' + hostname);
                    return;
                };
            },
            
            // Bypass for Android's SSLSocketFactory
            sslSocketFactory: function() {
                const SSLSocketFactory = Java.use('javax.net.ssl.SSLSocketFactory');
                const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
                
                // Create a custom TrustManager that trusts all certificates
                const TrustManagers = [Java.registerClass({
                    name: 'com.example.TrustAllCerts',
                    implements: [X509TrustManager],
                    methods: {
                        checkClientTrusted: function(chain, authType) {
                            console.log('[*] Bypassing client certificate check');
                        },
                        checkServerTrusted: function(chain, authType) {
                            console.log('[*] Bypassing server certificate check');
                        },
                        getAcceptedIssuers: function() {
                            return [];
                        }
                    }
                }).$new()];
                
                // Override getDefault() to return our custom TrustManager
                const TrustManagerFactory = Java.use('javax.net.ssl.TrustManagerFactory');
                TrustManagerFactory.getTrustManagers.implementation = function() {
                    console.log('[*] Overriding TrustManagerFactory.getTrustManagers()');
                    return TrustManagers;
                };
                
                // Override getDefault() to return our custom SSLSocketFactory
                SSLSocketFactory.getDefault.overload().implementation = function() {
                    console.log('[*] Overriding SSLSocketFactory.getDefault()');
                    const sslContext = Java.use('javax.net.ssl.SSLContext').getInstance('TLS');
                    sslContext.init(null, TrustManagers, null);
                    return sslContext.getSocketFactory();
                };
            },
            
            // Bypass for Android's HostnameVerifier
            hostnameVerifier: function() {
                const HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
                
                // Create a custom HostnameVerifier that verifies all hosts
                const AllHostsValid = Java.registerClass({
                    name: 'com.example.AllHostsValid',
                    implements: [HostnameVerifier],
                    methods: {
                        verify: function(hostname, session) {
                            console.log('[*] Bypassing hostname verification for: ' + hostname);
                            return true;
                        }
                    }
                }).$new();
                
                // Override the default HostnameVerifier
                const HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
                HttpsURLConnection.setDefaultHostnameVerifier(AllHostsValid);
                
                // Also override the instance method
                HttpsURLConnection.setHostnameVerifier.implementation = function(verifier) {
                    console.log('[*] Overriding setHostnameVerifier()');
                    return this.setHostnameVerifier(AllHostsValid);
                };
            },
            
            // Initialize all bypasses
            init: function() {
                console.log('[*] Initializing SSL pinning bypasses');
                
                // Try to apply all bypasses
                const bypasses = [
                    'okhttp',
                    'webview',
                    'trustmanager',
                    'networkSecurityConfig',
                    'certificatePinner',
                    'sslSocketFactory',
                    'hostnameVerifier'
                ];
                
                for (const bypass of bypasses) {
                    try {
                        this[bypass]();
                        console.log(`[+] Successfully applied ${bypass} bypass`);
                    } catch (e) {
                        console.log(`[-] Failed to apply ${bypass} bypass: ${e}`);
                    }
                }
                
                console.log('[*] SSL pinning bypasses initialized');
            }
        };
        
        // Initialize SSL pinning bypasses
        setTimeout(function() {
            try {
                sslPinningBypass.init();
                send({status: 'success', message: 'SSL pinning bypasses initialized'});
            } catch (e) {
                console.error('Error initializing SSL bypasses: ' + e);
                send({status: 'error', message: 'Failed to initialize SSL bypasses: ' + e});
            }
        }, 0);
        
        // Keep the script alive
        setInterval(function() {
            // Do nothing, just keep the script alive
        }, 1000);
        
        console.log('[*] SSL Pinning Bypass Script Loaded');
        """,
        
        'android_root_detection_bypass': """
        // Android Root Detection Bypass
        // Bypasses common root detection mechanisms
        
        console.log('[*] Starting Root Detection Bypass Script');
        
        // Common root detection bypasses
        const rootDetectionBypass = {
            // Bypass SuperUser.apk check
            checkSuperUserApk: function() {
                const File = Java.use('java.io.File');
                
                // Override exists() method to return false for common root files
                File.exists.implementation = function() {
                    const path = this.getAbsolutePath();
                    const rootFiles = [
                        '/system/app/Superuser.apk',
                        '/sbin/su',
                        '/system/bin/su',
                        '/system/xbin/su',
                        '/data/local/xbin/su',
                        '/data/local/bin/su',
                        '/system/sd/xbin/su',
                        '/system/bin/failsafe/su',
                        '/data/local/su',
                        '/su/bin/su'
                    ];
                    
                    if (rootFiles.some(file => path.startsWith(file))) {
                        console.log(`[*] Bypassing root file check: ${path}`);
                        return false;
                    }
                    
                    return this.exists();
                };
            },
            
            // Bypass su command check
            checkSuCommand: function() {
                const Runtime = Java.use('java.lang.Runtime');
                
                // Override exec() to block su commands
                Runtime.exec.overload('java.lang.String').implementation = function(command) {
                    if (command === 'su' || command.includes('su ')) {
                        console.log(`[*] Blocked su command: ${command}`);
                        throw new Error('Command not found');
                    }
                    return this.exec(command);
                };
                
                // Override exec(String[]) as well
                Runtime.exec.overload('[Ljava.lang.String;').implementation = function(commands) {
                    if (commands.some(cmd => cmd === 'su' || cmd.includes('su'))) {
                        console.log('[*] Blocked su command in array');
                        throw new Error('Command not found');
                    }
                    return this.exec(commands);
                };
            },
            
            // Bypass build tags check
            bypassBuildTags: function() {
                const Build = Java.use('android.os.Build');
                
                // Override TAGS to remove 'test-keys' and 'release-keys'
                Build.TAGS.value = 'release-keys';
                
                // Override FINGERPRINT to look like a non-rooted device
                Build.FINGERPRINT.value = Build.FINGERPRINT.value
                    .replace('test-keys', 'release-keys')
                    .replace('test-keys', 'release-keys');
                
                console.log('[*] Modified build tags and fingerprint');
            },
            
            // Bypass root prop check
            bypassRootProps: function() {
                const SystemProperties = Java.use('android.os.SystemProperties');
                
                // Override get() to return non-root values for root-related props
                const originalGet = SystemProperties.get.overload('java.lang.String');
                SystemProperties.get.overload('java.lang.String').implementation = function(key) {
                    if (key === 'ro.secure' || key === 'ro.debuggable' || key === 'service.adb.root') {
                        console.log(`[*] Bypassing root prop check: ${key}`);
                        return '0';
                    }
                    return originalGet.call(this, key);
                };
            },
            
            // Bypass Magisk/SuperSU detection
            bypassMagiskSu: function() {
                const File = Java.use('java.io.File');
                const ProcessBuilder = Java.use('java.lang.ProcessBuilder');
                
                // Hide Magisk and SuperSU files
                File.listFiles.implementation = function() {
                    const files = this.listFiles();
                    if (!files) return files;
                    
                    const filtered = [];
                    const hiddenDirs = ['magisk', 'su', 'supersu', 'superuser'];
                    
                    for (let i = 0; i < files.length; i++) {
                        const file = files[i];
                        const name = file.getName().toLowerCase();
                        
                        if (!hiddenDirs.some(dir => name.includes(dir))) {
                            filtered.push(file);
                        }
                    }
                    
                    return filtered;
                };
                
                // Block su commands in ProcessBuilder
                ProcessBuilder.$init.overload('[Ljava.lang.String;').implementation = function(commands) {
                    if (commands.some(cmd => cmd === 'su' || cmd.includes('su'))) {
                        console.log('[*] Blocked su command in ProcessBuilder');
                        throw new Error('Command not found');
                    }
                    return this.$init(commands);
                };
            },
            
            // Bypass SafetyNet attestation
            bypassSafetyNet: function() {
                const SafetyNetClient = Java.use('com.google.android.gms.safetynet.SafetyNetClient');
                const SafetyNetApi = Java.use('com.google.android.gms.safetynet.SafetyNet');
                
                // Override attest method to return a valid response
                SafetyNetClient.attest.overload('com.google.android.gms.common.api.GoogleApiClient', '[B').implementation = function(apiClient, nonce) {
                    console.log('[*] Bypassing SafetyNet attestation');
                    
                    // Create a mock PendingResult that returns a successful result
                    const PendingResult = Java.use('com.google.android.gms.common.api.PendingResult');
                    const SafetyNetApi$AttestationResult = Java.use('com.google.android.gms.safetynet.SafetyNetApi$AttestationResult');
                    const Status = Java.use('com.google.android.gms.common.api.Status');
                    const StatusCode = Java.use('com.google.android.gms.common.api.Status').STATUS_SUCCESS;
                    
                    // Create a mock result that indicates the device is not rooted
                    const mockResult = Java.registerClass({
                        name: 'com.example.MockAttestationResult',
                        implements: [SafetyNetApi$AttestationResult],
                        methods: {
                            getStatus: function() {
                                return Status.$new(StatusCode);
                            },
                            getJwsResult: function() {
                                // Return a valid JWS that indicates the device is not rooted
                                // This is a mock JWS - in a real bypass, you'd need to generate a valid one
                                return 'eyJhbGciOiJSUzI1NiIsIng1YyI6WyJNSUlFTHpDQ0E1T2dBd0lCQWdJQkFEQ0JvVEVUTUJFR0NTcUdTSWIzRFFFSEFhQ0JoZ1l';
                            }
                        }
                    }).$new();
                    
                    // Create a mock PendingResult that returns our mock result
                    const mockPendingResult = Java.registerClass({
                        name: 'com.example.MockPendingResult',
                        extends: PendingResult,
                        methods: {
                            await: function() {
                                return mockResult;
                            },
                            await$1: function(timeout, unit) {
                                return mockResult;
                            },
                            cancel: function() {
                                return false;
                            },
                            isCanceled: function() {
                                return false;
                            },
                            setResultCallback: function(callback) {
                                callback.onResult(mockResult);
                                return null;
                            },
                            setResultCallback$1: function(callback, time, unit) {
                                callback.onResult(mockResult);
                                return null;
                            }
                        }
                    }).$new();
                    
                    return mockPendingResult;
                };
            },
            
            // Initialize all bypasses
            init: function() {
                console.log('[*] Initializing root detection bypasses');
                
                // Try to apply all bypasses
                const bypasses = [
                    'checkSuperUserApk',
                    'checkSuCommand',
                    'bypassBuildTags',
                    'bypassRootProps',
                    'bypassMagiskSu',
                    'bypassSafetyNet'
                ];
                
                for (const bypass of bypasses) {
                    try {
                        this[bypass]();
                        console.log(`[+] Successfully applied ${bypass} bypass`);
                    } catch (e) {
                        console.log(`[-] Failed to apply ${bypass} bypass: ${e}`);
                    }
                }
                
                console.log('[*] Root detection bypasses initialized');
            }
        };
        
        // Initialize root detection bypasses
        setTimeout(function() {
            try {
                Java.perform(function() {
                    rootDetectionBypass.init();
                    send({status: 'success', message: 'Root detection bypasses initialized'});
                });
            } catch (e) {
                console.error('Error initializing root detection bypasses: ' + e);
                send({status: 'error', message: 'Failed to initialize root detection bypasses: ' + e});
            }
        }, 0);
        
        // Keep the script alive
        setInterval(function() {
            // Do nothing, just keep the script alive
        }, 1000);
        
        console.log('[*] Root Detection Bypass Script Loaded');
        """
    }
    
    def __init__(self, device_id: str = None):
        """Initialize the Frida script manager.
        
        Args:
            device_id: The ID of the device to connect to. If None, the first USB device will be used.
        """
        self.device_id = device_id
        self.device: Optional[FridaDevice] = None
        self.sessions: Dict[str, FridaScript] = {}
        self.message_handlers: Dict[str, Callable[[Dict, Any], None]] = {}
        
    async def connect(self) -> None:
        """Connect to the Frida device."""
        try:
            if self.device_id:
                self.device = await frida.get_device(self.device_id)
            else:
                self.device = await frida.get_usb_device()
            logger.info(f"Connected to Frida device: {self.device}")
        except Exception as e:
            logger.error(f"Failed to connect to Frida device: {str(e)}")
            raise
    
    async def list_processes(self) -> List[Dict]:
        """List running processes on the device."""
        if not self.device:
            await self.connect()
        
        try:
            processes = await self.device.enumerate_processes()
            return [{
                'pid': process.pid,
                'name': process.name,
                'parameters': process.parameters
            } for process in processes]
        except Exception as e:
            logger.error(f"Failed to list processes: {str(e)}")
            raise
    
    async def spawn(self, package_name: str) -> int:
        """Spawn a new process with the given package name.
        
        Args:
            package_name: The package name of the application to spawn.
            
        Returns:
            The PID of the spawned process.
        """
        if not self.device:
            await self.connect()
        
        try:
            pid = await self.device.spawn([package_name])
            logger.info(f"Spawned process {package_name} with PID {pid}")
            return pid
        except Exception as e:
            logger.error(f"Failed to spawn process {package_name}: {str(e)}")
            raise
    
    async def attach(self, target: str) -> str:
        """Attach to a running process.
        
        Args:
            target: The target process name or PID to attach to.
            
        Returns:
            The session ID.
        """
        if not self.device:
            await self.connect()
        
        try:
            session = await self.device.attach(target)
            session_id = str(id(session))
            self.sessions[session_id] = session
            logger.info(f"Attached to process {target} with session ID {session_id}")
            return session_id
        except Exception as e:
            logger.error(f"Failed to attach to process {target}: {str(e)}")
            raise
    
    async def load_script(self, session_id: str, script_name: str, script_code: str = None) -> str:
        """Load a Frida script into a session.
        
        Args:
            session_id: The session ID to load the script into.
            script_name: The name of the script to load.
            script_code: The script code to load. If None, a built-in script will be used.
            
        Returns:
            The script ID.
        """
        if session_id not in self.sessions:
            raise ValueError(f"No session found with ID {session_id}")
        
        session = self.sessions[session_id]
        
        # Use built-in script if no code is provided
        if script_code is None:
            if script_name not in self.BUILTIN_SCRIPTS:
                raise ValueError(f"No built-in script found with name {script_name}")
            script_code = self.BUILTIN_SCRIPTS[script_name]
        
        try:
            script = await session.create_script(script_code)
            
            # Set up message handler
            def on_message(message, data):
                self._handle_message(script_name, message, data)
            
            script.on('message', on_message)
            await script.load()
            
            script_id = f"{session_id}_{script_name}"
            self.sessions[session_id]._scripts[script_id] = script
            
            logger.info(f"Loaded script {script_name} into session {session_id}")
            return script_id
        except Exception as e:
            logger.error(f"Failed to load script {script_name}: {str(e)}")
            raise
    
    async def unload_script(self, script_id: str) -> None:
        """Unload a Frida script.
        
        Args:
            script_id: The ID of the script to unload.
        """
        for session_id, session in self.sessions.items():
            if hasattr(session, '_scripts') and script_id in session._scripts:
                try:
                    script = session._scripts[script_id]
                    await script.unload()
                    del session._scripts[script_id]
                    logger.info(f"Unloaded script {script_id}")
                    return
                except Exception as e:
                    logger.error(f"Failed to unload script {script_id}: {str(e)}")
                    raise
        
        raise ValueError(f"No script found with ID {script_id}")
    
    async def detach(self, session_id: str) -> None:
        """Detach from a session.
        
        Args:
            session_id: The ID of the session to detach from.
        """
        if session_id not in self.sessions:
            raise ValueError(f"No session found with ID {session_id}")
        
        try:
            # Unload all scripts in the session
            if hasattr(self.sessions[session_id], '_scripts'):
                for script_id in list(self.sessions[session_id]._scripts.keys()):
                    try:
                        await self.unload_script(script_id)
                    except Exception as e:
                        logger.warning(f"Failed to unload script {script_id}: {str(e)}")
            
            # Detach the session
            await self.sessions[session_id].detach()
            del self.sessions[session_id]
            logger.info(f"Detached from session {session_id}")
        except Exception as e:
            logger.error(f"Failed to detach from session {session_id}: {str(e)}")
            raise
    
    def register_message_handler(self, script_name: str, handler: Callable[[Dict, Any], None]) -> None:
        """Register a message handler for a script.
        
        Args:
            script_name: The name of the script to register the handler for.
            handler: The message handler function.
        """
        self.message_handlers[script_name] = handler
    
    def _handle_message(self, script_name: str, message: Dict, data: Any) -> None:
        """Handle a message from a Frida script.
        
        Args:
            script_name: The name of the script that sent the message.
            message: The message from the script.
            data: Additional data from the script.
        """
        try:
            if script_name in self.message_handlers:
                self.message_handlers[script_name](message, data)
            else:
                logger.debug(f"Received message from {script_name}: {message}")
                
                # Handle common message types
                if message.get('type') == 'send':
                    payload = message.get('payload', {})
                    if isinstance(payload, dict):
                        if 'status' in payload and 'message' in payload:
                            if payload['status'] == 'success':
                                logger.info(f"{script_name}: {payload['message']}")
                            elif payload['status'] == 'error':
                                logger.error(f"{script_name}: {payload['message']}")
                            else:
                                logger.info(f"{script_name}: {payload['message']}")
        except Exception as e:
            logger.error(f"Error handling message from {script_name}: {str(e)}")
    
    async def close(self) -> None:
        """Close all sessions and clean up resources."""
        for session_id in list(self.sessions.keys()):
            try:
                await self.detach(session_id)
            except Exception as e:
                logger.warning(f"Error detaching from session {session_id}: {str(e)}")
        
        self.sessions.clear()
        self.device = None
        logger.info("Frida script manager closed")

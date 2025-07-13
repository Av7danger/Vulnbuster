"""
Advanced Platform-Specific Hooks for Mobile Security Analysis.

This module provides specialized hooks for Android and iOS to detect advanced
security issues and suspicious behaviors during runtime.
"""
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Any, Callable, Set, Tuple
import re

from ..models import Finding, Severity, Platform
from .dynamic_analyzer import DynamicAnalyzer, HookConfig, HookType

class HookCategory(Enum):
    """Categories for advanced hooks."""
    IPC = "Inter-Process Communication"
    SENSORS = "Sensor Usage"
    PERMISSIONS = "Runtime Permissions"
    BACKGROUND = "Background Operations"
    CRYPTO = "Cryptography"
    NETWORK = "Network Operations"
    STORAGE = "Data Storage"
    UI = "User Interface"
    NATIVE = "Native Code"
    TELEPHONY = "Telephony Services"
    LOCATION = "Location Services"
    BIOMETRICS = "Biometric Authentication"
    KEYSTORE = "Secure Key Storage"

@dataclass
class AdvancedHook:
    """Configuration for advanced platform-specific hooks."""
    name: str
    category: HookCategory
    description: str
    platform: Platform
    hooks: List[HookConfig]
    severity: Severity = Severity.MEDIUM
    enabled: bool = True
    params: Dict[str, Any] = field(default_factory=dict)

class AdvancedHooks:
    """Manager for advanced platform-specific hooks."""
    
    def __init__(self, platform: Platform):
        """Initialize with target platform."""
        self.platform = platform
        self.hooks: Dict[str, AdvancedHook] = {}
        self._init_platform_hooks()
    
    def _init_platform_hooks(self) -> None:
        """Initialize platform-specific hooks."""
        if self.platform == Platform.ANDROID:
            self._init_android_hooks()
        elif self.platform == Platform.IOS:
            self._init_ios_hooks()
    
    def _init_android_hooks(self) -> None:
        """Initialize Android-specific hooks."""
        # IPC Hooks
        self.add_hook(AdvancedHook(
            name="binder_transaction",
            category=HookCategory.IPC,
            description="Monitor Binder transactions for suspicious IPC",
            platform=Platform.ANDROID,
            severity=Severity.HIGH,
            hooks=[
                HookConfig(
                    name="binder_transaction",
                    type=HookType.NATIVE_FUNCTION,
                    target="android_os_BinderProxy_transact",
                    on_enter="""
                    var code = args[1];
                    var data = args[2];
                    var code_name = getBinderTransactionCode(code);
                    
                    var context = {
                        'code': code,
                        'code_name': code_name,
                        'data_size': data ? data.readByteArray(data.getDataCapacity()).length : 0,
                        'stack_trace': Thread.backtrace(this.context, Backtracer.ACCURATE)
                    };
                    
                    sendData('binder_transaction', context);
                    """
                )
            ]
        ))
        
        # Cryptography Hooks
        self.add_hook(AdvancedHook(
            name="insecure_crypto_usage",
            category=HookCategory.CRYPTO,
            description="Detect insecure cryptographic operations",
            platform=Platform.ANDROID,
            severity=Severity.HIGH,
            hooks=[
                HookConfig(
                    name="insecure_cipher_instance",
                    type=HookType.JAVA_METHOD,
                    target="javax.crypto.Cipher.getInstance",
                    on_enter="""
                    var algorithm = args[0];
                    if (algorithm) {
                        var weak_algorithms = [
                            'DES', 'DESede', 'RC2', 'RC4', 'Blowfish',
                            'AES/ECB/NoPadding', 'AES/ECB/PKCS5Padding',
                            'RSA/ECB/NoPadding', 'RSA/ECB/PKCS1Padding',
                            'SHA1PRNG'
                        ];
                        
                        if (weak_algorithms.some(function(alg) { 
                            return algorithm.toString().toUpperCase().includes(alg.toUpperCase()); 
                        })) {
                            var context = {
                                'algorithm': algorithm.toString(),
                                'stack_trace': Thread.backtrace(this.context, Backtracer.ACCURATE)
                            };
                            sendData('insecure_crypto_usage', context);
                        }
                    }
                    """
                )
            ]
        ))
        
        # WebView Hooks
        self.add_hook(AdvancedHook(
            name="webview_security",
            category=HookCategory.UI,
            description="Detect insecure WebView configurations",
            platform=Platform.ANDROID,
            severity=Severity.HIGH,
            hooks=[
                HookConfig(
                    name="webview_set_javascript_enabled",
                    type=HookType.JAVA_METHOD,
                    target="android.webkit.WebSettings.setJavaScriptEnabled",
                    on_enter="""
                    var enabled = args[0];
                    if (enabled) {
                        var context = {
                            'javascript_enabled': enabled,
                            'class': this.constructor.name,
                            'stack_trace': Thread.backtrace(this.context, Backtracer.ACCURATE)
                        };
                        sendData('webview_insecure_config', context);
                    }
                    """
                ),
                HookConfig(
                    name="webview_set_allow_file_access",
                    type=HookType.JAVA_METHOD,
                    target="android.webkit.WebSettings.setAllowFileAccess",
                    on_enter="""
                    var allowed = args[0];
                    if (allowed) {
                        var context = {
                            'file_access_allowed': allowed,
                            'class': this.constructor.name,
                            'stack_trace': Thread.backtrace(this.context, Backtracer.ACCURATE)
                        };
                        sendData('webview_insecure_config', context);
                    }
                    """
                )
            ]
        ))
        
        # Sensor Hooks
        self.add_hook(AdvancedHook(
            name="sensor_usage",
            category=HookCategory.SENSORS,
            description="Monitor sensor usage for potential privacy issues",
            platform=Platform.ANDROID,
            hooks=[
                HookConfig(
                    name="sensor_manager_register_listener",
                    type=HookType.JAVA_METHOD,
                    target="android.hardware.SensorManager.registerListener",
                    on_enter="""
                    var sensor = args[1];
                    if (sensor) {
                        var context = {
                            'sensor_name': sensor.getName(),
                            'sensor_type': sensor.getType(),
                            'sampling_period': args[2],
                            'max_report_latency': args.length > 3 ? args[3] : 'N/A',
                            'stack_trace': Thread.backtrace(this.context, Backtracer.ACCURATE)
                        };
                        sendData('sensor_usage', context);
                    }
                    """
                )
            ]
        ))
        
        # Background Service Hooks
        self.add_hook(AdvancedHook(
            name="background_service_operations",
            category=HookCategory.BACKGROUND,
            description="Monitor background service operations",
            platform=Platform.ANDROID,
            hooks=[
                HookConfig(
                    name="start_service",
                    type=HookType.JAVA_METHOD,
                    target="android.content.Context.startService",
                    on_enter="""
                    var intent = args[1];
                    if (intent) {
                        var context = {
                            'action': intent.getAction(),
                            'component': intent.getComponent() ? intent.getComponent().getClassName() : 'null',
                            'extras': intent.getExtras() ? JSON.stringify(intent.getExtras()) : '{}',
                            'stack_trace': Thread.backtrace(this.context, Backtracer.ACCURATE)
                        };
                        sendData('background_service_start', context);
                    }
                    """
                ),
                HookConfig(
                    name="start_foreground_service",
                    type=HookType.JAVA_METHOD,
                    target="android.content.Context.startForegroundService",
                    on_enter="""
                    var intent = args[1];
                    if (intent) {
                        var context = {
                            'action': intent.getAction(),
                            'component': intent.getComponent() ? intent.getComponent().getClassName() : 'null',
                            'extras': intent.getExtras() ? JSON.stringify(intent.getExtras()) : '{}',
                            'stack_trace': Thread.backtrace(this.context, Backtracer.ACCURATE)
                        };
                        sendData('foreground_service_start', context);
                    }
                    """
                )
            ]
        ))
        
        # Cryptography Hooks
        self.add_hook(AdvancedHook(
            name="crypto_operations",
            category=HookCategory.CRYPTO,
            description="Monitor cryptographic operations for weak implementations",
            platform=Platform.ANDROID,
            severity=Severity.HIGH,
            hooks=[
                HookConfig(
                    name="key_generator_init",
                    type=HookType.JAVA_METHOD,
                    target="javax.crypto.KeyGenerator.init",
                    on_enter="""
                    var keySize = -1;
                    var algorithm = "";
                    
                    if (args.length > 0) {
                        // Get key size if available
                        if (args[0] && args[0].getClass().getName().equals('java.security.spec.AlgorithmParameterSpec')) {
                            // Handle AlgorithmParameterSpec
                            var spec = args[0];
                            if (spec.getClass().getName().equals('javax.crypto.spec.IvParameterSpec')) {
                                algorithm = "AES/CBC/PKCS5Padding";
                            }
                        } else if (args.length > 0 && typeof args[0] === 'number') {
                            keySize = args[0];
                        }
                        
                        // Get algorithm from KeyGenerator instance
                        try {
                            var kg = this;
                            algorithm = kg.getAlgorithm();
                        } catch (e) {}
                        
                        var context = {
                            'algorithm': algorithm,
                            'key_size': keySize,
                            'stack_trace': Thread.backtrace(this.context, Backtracer.ACCURATE)
                        };
                        
                        sendData('key_generator_init', context);
                    }
                    """
                ),
                HookConfig(
                    name="cipher_init",
                    type=HookType.JAVA_METHOD,
                    target="javax.crypto.Cipher.init",
                    on_enter="""
                    var opmode = args[0];
                    var key = args[1];
                    var params = args.length > 2 ? args[2] : null;
                    
                    var keyAlgorithm = "";
                    var keyFormat = "";
                    var keySize = -1;
                    var transformation = "";
                    
                    try {
                        // Get key information
                        if (key) {
                            keyAlgorithm = key.getAlgorithm() || "";
                            keyFormat = key.getFormat() || "";
                            
                            // Try to get key size
                            if (keyAlgorithm && key.getEncoded) {
                                var encoded = key.getEncoded();
                                if (encoded) {
                                    keySize = encoded.length * 8; // bits
                                }
                            }
                        }
                        
                        // Get transformation from Cipher instance
                        var cipher = this;
                        transformation = cipher.getAlgorithm() || "";
                        
                        var context = {
                            'opmode': opmode,
                            'key_algorithm': keyAlgorithm,
                            'key_format': keyFormat,
                            'key_size': keySize,
                            'transformation': transformation,
                            'params': params ? params.toString() : 'null',
                            'stack_trace': Thread.backtrace(this.context, Backtracer.ACCURATE)
                        };
                        
                        // Check for weak configurations
                        var weak = [];
                        
                        // Check for weak algorithms
                        var weakAlgorithms = ["DES", "DESede", "RC2", "RC4"];
                        for (var i = 0; i < weakAlgorithms.length; i++) {
                            if (transformation.indexOf(weakAlgorithms[i]) !== -1 || 
                                keyAlgorithm.indexOf(weakAlgorithms[i]) !== -1) {
                                weak.push('weak_algorithm:' + weakAlgorithms[i]);
                            }
                        }
                        
                        // Check for weak key sizes
                        if (keySize > 0) {
                            if ((transformation.indexOf('AES') !== -1 || keyAlgorithm.indexOf('AES') !== -1) && keySize < 128) {
                                weak.push('weak_key_size:' + keySize + ' bits');
                            } else if ((transformation.indexOf('RSA') !== -1 || keyAlgorithm.indexOf('RSA') !== -1) && keySize < 2048) {
                                weak.push('weak_key_size:' + keySize + ' bits');
                            } else if ((transformation.indexOf('EC') !== -1 || keyAlgorithm.indexOf('EC') !== -1) && keySize < 224) {
                                weak.push('weak_key_size:' + keySize + ' bits');
                            }
                        }
                        
                        // Check for insecure modes/paddings
                        if (transformation.match(/(ECB|CBC|PKCS5Padding|PKCS1Padding)/)) {
                            if (transformation.indexOf('ECB') !== -1) {
                                weak.push('insecure_mode:ECB');
                            }
                            if (transformation.indexOf('CBC') !== -1 && transformation.indexOf('GCM') === -1) {
                                weak.push('insecure_mode:CBC without authentication');
                            }
                            if (transformation.indexOf('PKCS5Padding') !== -1 || transformation.indexOf('PKCS1Padding') !== -1) {
                                weak.push('insecure_padding:PKCS#5/PKCS#1');
                            }
                        }
                        
                        if (weak.length > 0) {
                            context['weak_configurations'] = weak;
                            context['severity'] = 'HIGH';
                        }
                        
                        sendData('cipher_init', context);
                        
                    } catch (e) {
                        console.error('Error in cipher.init hook:', e);
                    }
                    """
                )
            ]
        ))
        
        # Network Security Hooks
        self.add_hook(AdvancedHook(
            name="network_security",
            category=HookCategory.NETWORK,
            description="Monitor network security configurations and operations",
            platform=Platform.ANDROID,
            severity=Severity.HIGH,
            hooks=[
                HookConfig(
                    name="ssl_socket_connect",
                    type=HookType.JAVA_METHOD,
                    target="javax.net.ssl.SSLSocket.connect",
                    on_enter="""
                    var socket = this;
                    var host = '';
                    var port = -1;
                    
                    try {
                        // Get host and port from the SocketAddress
                        var address = args[0];
                        if (address) {
                            if (address.getAddress) {
                                host = address.getHostName() || '';
                                port = address.getPort();
                            } else if (address.getHostString) {
                                // For InetSocketAddress
                                host = address.getHostString() || '';
                                port = address.getPort();
                            }
                        }
                        
                        // Get SSL context and protocols
                        var sslContext = null;
                        var sslParameters = null;
                        var enabledProtocols = [];
                        var enabledCipherSuites = [];
                        
                        try {
                            sslParameters = socket.getSSLParameters();
                            if (sslParameters) {
                                var protocols = sslParameters.getProtocols();
                                if (protocols) {
                                    enabledProtocols = Array.from(protocols);
                                }
                                
                                var ciphers = sslParameters.getCipherSuites();
                                if (ciphers) {
                                    enabledCipherSuites = Array.from(ciphers);
                                }
                            }
                            
                            // Get SSL context if available
                            if (socket.getSSLContext) {
                                sslContext = socket.getSSLContext();
                            }
                            
                        } catch (e) {
                            console.error('Error getting SSL parameters:', e);
                        }
                        
                        var context = {
                            'host': host,
                            'port': port,
                            'enabled_protocols': enabledProtocols,
                            'enabled_ciphers': enabledCipherSuites,
                            'ssl_context': sslContext ? sslContext.toString() : 'null',
                            'stack_trace': Thread.backtrace(this.context, Backtracer.ACCURATE)
                        };
                        
                        // Check for weak configurations
                        var weak = [];
                        
                        // Check for weak protocols
                        var weakProtocols = ['SSLv3', 'TLSv1', 'TLSv1.1'];
                        for (var i = 0; i < weakProtocols.length; i++) {
                            if (enabledProtocols.indexOf(weakProtocols[i]) !== -1) {
                                weak.push('weak_protocol:' + weakProtocols[i]);
                            }
                        }
                        
                        // Check for weak ciphers
                        var weakCiphers = [
                            '_NULL_', '_EXPORT_', '_DES_', '_RC2_', '_RC4_', '_MD5_', 
                            '_ANON_', '_ADH_', '_KRB5_', '_3DES_', '_CBC_'
                        ];
                        
                        for (var i = 0; i < enabledCipherSuites.length; i++) {
                            var cipher = enabledCipherSuites[i];
                            for (var j = 0; j < weakCiphers.length; j++) {
                                if (cipher.indexOf(weakCiphers[j]) !== -1) {
                                    weak.push('weak_cipher:' + cipher);
                                    break;
                                }
                            }
                        }
                        
                        if (weak.length > 0) {
                            context['weak_configurations'] = weak;
                            context['severity'] = 'HIGH';
                        }
                        
                        sendData('ssl_socket_connect', context);
                        
                    } catch (e) {
                        console.error('Error in SSLSocket.connect hook:', e);
                    }
                    """
                )
            ]
        ))
        
        # File Operations Hooks
        self.add_hook(AdvancedHook(
            name="file_operations",
            category=HookCategory.STORAGE,
            description="Monitor file operations for sensitive data exposure",
            platform=Platform.ANDROID,
            hooks=[
                HookConfig(
                    name="file_output_stream_init",
                    type=HookType.JAVA_METHOD,
                    target="java.io.FileOutputStream.$init",
                    on_enter="""
                    var file = args[0];
                    var path = file ? file.getAbsolutePath() : '';
                    
                    // Check for sensitive file paths
                    if (path) {
                        var sensitiveDirs = [
                            '/data/data/', '/sdcard/', '/mnt/sdcard/', '/storage/',
                            '/shared_prefs/', '/databases/', '/app_webview/'
                        ];
                        
                        var isSensitive = sensitiveDirs.some(function(dir) {
                            return path.indexOf(dir) !== -1;
                        });
                        
                        if (isSensitive) {
                            var context = {
                                'path': path,
                                'operation': 'file_write',
                                'stack_trace': Thread.backtrace(this.context, Backtracer.ACCURATE)
                            };
                            
                            sendData('sensitive_file_operation', context);
                        }
                    }
                    """
                )
            ]
        ))
    
    def _init_ios_hooks(self) -> None:
        """Initialize iOS-specific hooks."""
        # Keychain Hooks
        self.add_hook(AdvancedHook(
            name="insecure_keychain_usage",
            category=HookCategory.KEYSTORE,
            description="Detect insecure Keychain item storage",
            platform=Platform.IOS,
            severity=Severity.HIGH,
            hooks=[
                HookConfig(
                    name="secitem_add_insecure",
                    type=HookType.NATIVE_FUNCTION,
                    target="SecItemAdd",
                    on_enter="""
                    var query = args[0];
                    var result = args[1];
                    
                    // Check for kSecAttrAccessible values that don't require passcode
                    var accessibleValues = [
                        'kSecAttrAccessibleAlways',
                        'kSecAttrAccessibleAlwaysThisDeviceOnly',
                        'kSecAttrAccessibleAfterFirstUnlock',
                        'kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly'
                    ];
                    
                    var accessible = ObjC.Object(query).objectForKey_('kSecAttrAccessible');
                    if (accessible && accessibleValues.includes(accessible.toString())) {
                        var context = {
                            'insecure_accessibility': accessible.toString(),
                            'stack_trace': Thread.backtrace(this.context, Backtracer.ACCURATE)
                        };
                        sendData('insecure_keychain_usage', context);
                    }
                    """
                )
            ]
        ))
        
        # Data Protection Hooks
        self.add_hook(AdvancedHook(
            name="data_protection",
            category=HookCategory.STORAGE,
            description="Check for weak data protection classes",
            platform=Platform.IOS,
            severity=Severity.HIGH,
            hooks=[
                HookConfig(
                    name="nsdata_write_to_file",
                    type=HookType.OBJC_METHOD,
                    target="-[NSData writeToFile:options:error:]",
                    on_enter="""
                    var options = args[1];
                    // Check if NSDataWritingFileProtectionNone is used
                    if ((options & 0x10000000) === 0) {
                        var context = {
                            'file_protection': 'NSDataWritingFileProtectionNone',
                            'file_path': args[0],
                            'stack_trace': Thread.backtrace(this.context, Backtracer.ACCURATE)
                        };
                        sendData('weak_file_protection', context);
                    }
                    """
                )
            ]
        ))
        
        # WebView Hooks for iOS
        self.add_hook(AdvancedHook(
            name="wkwebview_security",
            category=HookCategory.UI,
            description="Detect insecure WKWebView configurations",
            platform=Platform.IOS,
            severity=Severity.HIGH,
            hooks=[
                HookConfig(
                    name="wkwebview_javascript_enabled",
                    type=HookType.OBJC_METHOD,
                    target="-[WKWebViewConfiguration setAllowsInlineMediaPlayback:]",
                    on_enter="""
                    var enabled = args[0];
                    if (enabled) {
                        var context = {
                            'inline_media_playback': enabled,
                            'class': this.constructor.name,
                            'stack_trace': Thread.backtrace(this.context, Backtracer.ACCURATE)
                        };
                        sendData('insecure_webview_config', context);
                    }
                    """
                ),
                HookConfig(
                    name="wkwebview_javascript_enabled",
                    type=HookType.OBJC_METHOD,
                    target="-[WKWebViewConfiguration setAllowsInlineMediaPlayback:]",
                    on_enter="""
                    var enabled = args[0];
                    if (enabled) {
                        var context = {
                            'inline_media_playback': enabled,
                            'class': this.constructor.name,
                            'stack_trace': Thread.backtrace(this.context, Backtracer.ACCURATE)
                        };
                        sendData('insecure_webview_config', context);
                    }
                    """
                )
            ]
        ))
        
        # URL Loading Hooks
        self.add_hook(AdvancedHook(
            name="insecure_url_loading",
            category=HookCategory.NETWORK,
            description="Detect insecure URL loading",
            platform=Platform.IOS,
            severity=Severity.MEDIUM,
            hooks=[
                HookConfig(
                    name="nsurlconnection_insecure_load",
                    type=HookType.OBJC_METHOD,
                    target="+[NSURLConnection connectionWithRequest:delegate:]",
                    on_enter="""
                    var request = args[0];
                    var url = request.URL();
                    var scheme = url.scheme();
                    
                    if (scheme && scheme.toString().toLowerCase() === 'http') {
                        var context = {
                            'url': url.absoluteString().toString(),
                            'stack_trace': Thread.backtrace(this.context, Backtracer.ACCURATE)
                        };
                        sendData('insecure_url_loading', context);
                    }
                    """
                )
            ]
        ))
        
        # Pasteboard Hooks
        self.add_hook(AdvancedHook(
            name="pasteboard_usage",
            category=HookCategory.STORAGE,
            description="Monitor UIPasteboard usage for potential data leaks",
            platform=Platform.IOS,
            severity=Severity.MEDIUM,
            hooks=[
                HookConfig(
                    name="uipasteboard_set_string",
                    type=HookType.OBJC_METHOD,
                    target="-[UIPasteboard setString:forPasteboardType:]",
                    on_enter="""
                    var string = args[0];
                    var type = args[1];
                    
                    // Check for sensitive data patterns
                    var sensitivePatterns = [
                        /\bpassword\b/i,
                        /\bpasswd\b/i,
                        /\bsecret\b/i,
                        /\bapi[_-]?key\b/i,
                        /\baccess[_-]?token\b/i,
                        /\bcredit[_-]?card\b/i,
                        /\bcc[_-]?num(ber)?\b/i,
                        /\bssn\b|\bsocial[_-]?security[_-]?num(ber)?\b/i
                    ];
                    
                    var strValue = string ? string.toString() : '';
                    var isSensitive = sensitivePatterns.some(function(pattern) {
                        return pattern.test(strValue) || pattern.test(type.toString());
                    });
                    
                    if (isSensitive) {
                        var context = {
                            'pasteboard_type': type.toString(),
                            'content_preview': strValue.length > 50 ? 
                                strValue.substring(0, 50) + '...' : strValue,
                            'content_length': strValue.length,
                            'stack_trace': Thread.backtrace(this.context, Backtracer.ACCURATE)
                        };
                        sendData('sensitive_pasteboard_usage', context);
                    }
                    """
                )
            ]
        ))
        self.add_hook(AdvancedHook(
            name="keychain_operations",
            category=HookCategory.KEYSTORE,
            description="Monitor Keychain operations for sensitive data",
            platform=Platform.IOS,
            severity=Severity.HIGH,
            hooks=[
                HookConfig(
                    name="sec_item_add",
                    type=HookType.API_CALL,
                    target="SecItemAdd",
                    on_enter="""
                    var query = args[0];
                    var result = args[1];
                    
                    if (query) {
                        var context = {
                            'class': query[kSecClass] ? query[kSecClass].toString() : '',
                            'account': query[kSecAttrAccount],
                            'service': query[kSecAttrService],
                            'accessible': query[kSecAttrAccessible],
                            'synchronizable': query[kSecAttrSynchronizable],
                            'value_data': query[kSecValueData] ? '***' : null,
                            'operation': 'add',
                            'stack_trace': Thread.backtrace(this.context, Backtracer.ACCURATE)
                        };
                        
                        // Check for insecure storage
                        var insecure = false;
                        var accessible = context['accessible'];
                        if (accessible && 
                            (accessible.indexOf('kSecAttrAccessibleAlways') !== -1 ||
                             accessible.indexOf('kSecAttrAccessibleAfterFirstUnlock') !== -1 ||
                             accessible.indexOf('kSecAttrAccessibleWhenUnlockedThisDeviceOnly') === -1)) {
                            context['insecure_storage'] = true;
                            context['severity'] = 'HIGH';
                        }
                        
                        sendData('keychain_operation', context);
                    }
                    """
                ),
                HookConfig(
                    name="sec_item_copy_matching",
                    type=HookType.API_CALL,
                    target="SecItemCopyMatching",
                    on_enter="""
                    var query = args[0];
                    var result = args[1];
                    
                    if (query) {
                        var context = {
                            'class': query[kSecClass] ? query[kSecClass].toString() : '',
                            'account': query[kSecAttrAccount],
                            'service': query[kSecAttrService],
                            'operation': 'query',
                            'stack_trace': Thread.backtrace(this.context, Backtracer.ACCURATE)
                        };
                        
                        sendData('keychain_operation', context);
                    }
                    """,
                    on_leave="""
                    var query = args[0];
                    var result = args[1];
                    
                    if (result && result.value) {
                        var data = result.value;
                        if (data && data.constructor.name === 'NSConcreteMutableData') {
                            var context = {
                                'class': query[kSecClass] ? query[kSecClass].toString() : '',
                                'account': query[kSecAttrAccount],
                                'service': query[kSecAttrService],
                                'data_length': data.length(),
                                'data_preview': data.bytes().readCString(32) + (data.length() > 32 ? '...' : ''),
                                'operation': 'query_result',
                                'stack_trace': Thread.backtrace(this.context, Backtracer.ACCURATE)
                            };
                            
                            sendData('keychain_data_access', context);
                        }
                    }
                    """
                )
            ]
        ))
        
        # NSUserDefaults Hooks
        self.add_hook(AdvancedHook(
            name="user_defaults",
            category=HookCategory.STORAGE,
            description="Monitor NSUserDefaults for sensitive data storage",
            platform=Platform.IOS,
            hooks=[
                HookConfig(
                    name="user_defaults_set",
                    type=HookType.API_CALL,
                    target="-[NSUserDefaults setObject:forKey:]",
                    on_enter="""
                    var obj = args[2];
                    var key = args[3];
                    
                    if (key) {
                        var context = {
                            'key': key,
                            'value_type': obj ? obj.constructor.name : 'null',
                            'value_preview': obj ? obj.toString().substring(0, 100) : 'null',
                            'operation': 'set',
                            'stack_trace': Thread.backtrace(this.context, Backtracer.ACCURATE)
                        };
                        
                        // Check for sensitive keys
                        var sensitiveKeys = ['password', 'token', 'secret', 'key', 'auth', 'credential'];
                        for (var i = 0; i < sensitiveKeys.length; i++) {
                            if (key.toLowerCase().indexOf(sensitiveKeys[i]) !== -1) {
                                context['sensitive_key'] = true;
                                context['severity'] = 'HIGH';
                                break;
                            }
                        }
                        
                        sendData('user_defaults_operation', context);
                    }
                    """
                )
            ]
        ))
        
        # URL Loading Hooks
        self.add_hook(AdvancedHook(
            name="url_loading",
            category=HookCategory.NETWORK,
            description="Monitor URL loading for insecure connections",
            platform=Platform.IOS,
            severity=Severity.HIGH,
            hooks=[
                HookConfig(
                    name="nsurl_request",
                    type=HookType.API_CALL,
                    target="-[NSURLRequest requestWithURL:]",
                    on_enter="""
                    var url = args[2];
                    if (url) {
                        var urlStr = url.absoluteString();
                        if (urlStr && urlStr.toLowerCase().startsWith('http:')) {
                            var context = {
                                'url': urlStr,
                                'insecure': true,
                                'stack_trace': Thread.backtrace(this.context, Backtracer.ACCURATE)
                            };
                            
                            sendData('insecure_url_loading', context);
                        }
                    }
                    """
                )
            ]
        ))
    
    def add_hook(self, hook: AdvancedHook) -> None:
        """Add an advanced hook configuration."""
        if hook.platform == self.platform:
            self.hooks[hook.name] = hook
    
    def get_hooks(self) -> List[AdvancedHook]:
        """Get all configured hooks for the current platform."""
        return list(self.hooks.values())
    
    def get_hook_configs(self) -> List[HookConfig]:
        """Get all hook configurations as a flat list."""
        configs = []
        for hook in self.hooks.values():
            configs.extend(hook.hooks)
        return configs
    
    def enable_hook(self, name: str, enable: bool = True) -> bool:
        """Enable or disable a hook by name."""
        if name in self.hooks:
            self.hooks[name].enabled = enable
            for hook in self.hooks[name].hooks:
                hook.enabled = enable
            return True
        return False
    
    def get_findings(self) -> List[Finding]:
        """Generate findings from hook data."""
        findings = []
        
        # This would be populated from the dynamic analysis results
        # For now, return an empty list
        
        return findings

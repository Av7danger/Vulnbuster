"""
Dynamic Analysis Module for Mobile Applications.

This module provides runtime analysis of mobile applications using Frida,
monitoring API calls, network activity, and other runtime behaviors to
identify security vulnerabilities.
"""
import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Callable, Awaitable, Tuple

import frida
from frida.core import Device as FridaDevice, Script as FridaScript

from ..models import Finding, Severity, Platform
from .frida_manager import FridaScriptManager

logger = logging.getLogger(__name__)

class HookType(Enum):
    """Types of function hooks for dynamic analysis."""
    JAVA_METHOD = "java_method"
    NATIVE_FUNCTION = "native_function"
    API_CALL = "api_call"
    NETWORK = "network"
    CRYPTO = "crypto"
    STORAGE = "storage"

@dataclass
class HookConfig:
    """Configuration for a function hook."""
    name: str
    type: HookType
    target: str
    on_enter: Optional[str] = None
    on_leave: Optional[str] = None
    enabled: bool = True
    params: Dict[str, Any] = field(default_factory=dict)

class DynamicAnalyzer:
    """Dynamic analyzer for mobile applications."""
    
    def __init__(self, platform: Platform, package_name: str, frida_manager: FridaScriptManager = None):
        """Initialize the dynamic analyzer.
        
        Args:
            platform: The target platform (Android/iOS).
            package_name: The package name or bundle ID of the target app.
            frida_manager: Optional FridaScriptManager instance.
        """
        self.platform = platform
        self.package_name = package_name
        self.frida_manager = frida_manager or FridaScriptManager()
        self.hooks: Dict[str, HookConfig] = {}
        self.session_id: Optional[str] = None
        self.script_id: Optional[str] = None
        self.message_handlers: Dict[str, Callable[[Dict, Any], None]] = {}
        self.findings: List[Finding] = []
        self._setup_default_hooks()
    
    def _setup_default_hooks(self) -> None:
        """Set up default hooks based on the platform."""
        if self.platform == Platform.ANDROID:
            self._setup_android_hooks()
        elif self.platform == Platform.IOS:
            self._setup_ios_hooks()
    
    def _setup_android_hooks(self) -> None:
        """Set up default hooks for Android."""
        # SSL/TLS related hooks
        self.add_hook(HookConfig(
            name="ssl_verify",
            type=HookType.JAVA_METHOD,
            target="javax.net.ssl.SSLContext.getInstance",
            on_enter=self._on_ssl_context_get_instance,
            params={"enabled": True}
        ))
        
        # Network related hooks
        self.add_hook(HookConfig(
            name="http_request",
            type=HookType.JAVA_METHOD,
            target="java.net.URL.openConnection",
            on_enter=self._on_http_request,
            params={"enabled": True}
        ))
        
        # Crypto related hooks
        self.add_hook(HookConfig(
            name="cipher_init",
            type=HookType.JAVA_METHOD,
            target="javax.crypto.Cipher.getInstance",
            on_enter=self._on_cipher_init,
            params={"enabled": True}
        ))
        
        # Storage related hooks
        self.add_hook(HookConfig(
            name="shared_prefs",
            type=HookType.JAVA_METHOD,
            target="android.content.SharedPreferences$Editor.putString",
            on_enter=self._on_shared_prefs_put,
            params={"enabled": True}
        ))
        
        # WebView related hooks
        self.add_hook(HookConfig(
            name="webview_load_url",
            type=HookType.JAVA_METHOD,
            target="android.webkit.WebView.loadUrl",
            on_enter=self._on_webview_load_url,
            params={"enabled": True}
        ))
    
    def _setup_ios_hooks(self) -> None:
        """Set up default hooks for iOS."""
        # SSL/TLS related hooks
        self.add_hook(HookConfig(
            name="nsurlsession_ssl",
            type=HookType.API_CALL,
            target="-[NSURLSessionDelegate URLSession:didReceiveChallenge:completionHandler:]",
            on_enter=self._on_nsurlsession_ssl,
            params={"enabled": True}
        ))
        
        # Network related hooks
        self.add_hook(HookConfig(
            name="nsurlconnection",
            type=HookType.API_CALL,
            target="[NSURLConnection sendSynchronousRequest:returningResponse:error:]",
            on_enter=self._on_nsurlconnection_request,
            params={"enabled": True}
        ))
        
        # Keychain related hooks
        self.add_hook(HookConfig(
            name="keychain_add",
            type=HookType.API_CALL,
            target="SecItemAdd",
            on_enter=self._on_keychain_add,
            params={"enabled": True}
        ))
        
        # UserDefaults related hooks
        self.add_hook(HookConfig(
            name="userdefaults_set",
            type=HookType.API_CALL,
            target="-[NSUserDefaults setObject:forKey:]",
            on_enter=self._on_userdefaults_set,
            params={"enabled": True}
        ))
    
    def add_hook(self, hook: HookConfig) -> None:
        """Add a hook configuration.
        
        Args:
            hook: The hook configuration to add.
        """
        self.hooks[hook.name] = hook
    
    def remove_hook(self, name: str) -> None:
        """Remove a hook by name.
        
        Args:
            name: The name of the hook to remove.
        """
        if name in self.hooks:
            del self.hooks[name]
    
    def register_message_handler(self, name: str, handler: Callable[[Dict, Any], None]) -> None:
        """Register a message handler for a specific hook.
        
        Args:
            name: The name of the hook to register the handler for.
            handler: The message handler function.
        """
        self.message_handlers[name] = handler
    
    async def start(self, spawn: bool = False) -> None:
        """Start the dynamic analysis.
        
        Args:
            spawn: Whether to spawn the app or attach to a running instance.
        """
        try:
            # Connect to the Frida device
            await self.frida_manager.connect()
            
            # Spawn or attach to the target process
            if spawn:
                pid = await self.frida_manager.spawn(self.package_name)
                self.session_id = await self.frida_manager.attach(pid)
            else:
                self.session_id = await self.frida_manager.attach(self.package_name)
            
            # Generate the Frida script for the hooks
            script = self._generate_script()
            
            # Register message handler
            def on_message(message, data):
                self._handle_message(message, data)
            
            # Load the script
            self.script_id = await self.frida_manager.load_script(
                self.session_id,
                "dynamic_analysis",
                script
            )
            
            # Start the app if we spawned it
            if spawn:
                await self.frida_manager.device.resume(pid)
            
            logger.info(f"Dynamic analysis started for {self.package_name}")
            
        except Exception as e:
            logger.error(f"Failed to start dynamic analysis: {str(e)}", exc_info=True)
            raise
    
    async def stop(self) -> None:
        """Stop the dynamic analysis and clean up resources."""
        try:
            if self.script_id and self.session_id:
                await self.frida_manager.unload_script(self.script_id)
                self.script_id = None
            
            if self.session_id:
                await self.frida_manager.detach(self.session_id)
                self.session_id = None
            
            logger.info("Dynamic analysis stopped")
            
        except Exception as e:
            logger.error(f"Error stopping dynamic analysis: {str(e)}", exc_info=True)
            raise
    
    def _generate_script(self) -> str:
        """Generate the Frida script for the configured hooks."""
        script_parts = ["'use strict';", "console.log('Dynamic analysis script loaded');"]
        
        # Add hook implementations
        for hook in self.hooks.values():
            if not hook.enabled:
                continue
                
            if hook.type == HookType.JAVA_METHOD:
                script_parts.append(self._generate_java_hook(hook))
            elif hook.type in [HookType.API_CALL, HookType.NATIVE_FUNCTION]:
                script_parts.append(self._generate_native_hook(hook))
        
        # Add helper functions
        script_parts.append("""
        function sendData(type, data) {
            send({
                type: type,
                payload: data
            });
        }
        
        function getStackTrace() {
            return Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress).join('\\n');
        }
        
        function getCurrentTime() {
            return new Date().toISOString();
        }
        
        function objToString(obj) {
            if (obj === null || obj === undefined) {
                return String(obj);
            }
            
            if (typeof obj === 'string') {
                return obj;
            }
            
            if (Array.isArray(obj)) {
                return '[' + obj.map(objToString).join(', ') + ']';
            }
            
            if (typeof obj === 'object') {
                try {
                    return JSON.stringify(obj);
                } catch (e) {
                    try {
                        var result = [];
                        for (var key in obj) {
                            if (obj.hasOwnProperty(key)) {
                                result.push(key + ': ' + objToString(obj[key]));
                            }
                        }
                        return '{' + result.join(', ') + '}';
                    } catch (e) {
                        return '[Object]';
                    }
                }
            }
            
            return String(obj);
        }
        """)
        
        return "\n".join(script_parts)
    
    def _generate_java_hook(self, hook: HookConfig) -> str:
        """Generate Frida script for a Java method hook."""
        target = hook.target
        
        # Parse class and method from target
        if '.' in target:
            class_name, method_name = target.rsplit('.', 1)
            class_name = class_name.replace('.', '/')
        else:
            class_name = target
            method_name = "*"
        
        # Generate hook code
        hook_code = f"""
        // Hook for {target}
        try {{
            var targetClass = Java.use('{class_name}');
            
            // Get all overloads of the method
            var overloads = targetClass['{method_name}'].overloads;
            
            for (var i = 0; i < overloads.length; i++) {{
                overloads[i].implementation = function() {{
                    // Prepare arguments
                    var args = [];
                    for (var j = 0; j < arguments.length; j++) {{
                        args.push(objToString(arguments[j]));
                    }}
                    
                    // Prepare context
                    var context = {{
                        timestamp: getCurrentTime(),
                        method: '{class_name}.{method_name}',
                        args: args,
                        this: objToString(this),
                        thread: Thread.currentThread().toString(),
                        stackTrace: getStackTrace()
                    }};
                    
                    // Call onEnter if provided
                    var onEnterResult = null;
                    if (typeof {hook.name}_onEnter === 'function') {{
                        try {{
                            onEnterResult = {hook.name}_onEnter(context, this, arguments);
                        }} catch (e) {{
                            console.error(`Error in {hook.name}_onEnter: ${{e}}`);
                        }}
                    }}
                    
                    // Call the original method
                    var result;
                    var exception = null;
                    
                    try {{
                        result = this[methodName].apply(this, arguments);
                    }} catch (e) {{
                        exception = e.toString();
                        throw e;
                    }} finally {{
                        // Call onLeave if provided
                        if (typeof {hook.name}_onLeave === 'function') {{
                            try {{
                                context.result = objToString(result);
                                context.exception = exception;
                                context.onEnterResult = onEnterResult;
                                
                                {hook.name}_onLeave(context, this, arguments, result, exception);
                            }} catch (e) {{
                                console.error(`Error in {hook.name}_onLeave: ${{e}}`);
                            }}
                        }}
                    }}
                    
                    return result;
                }};
            }}
            
            console.log(`[+] Hooked {target}`);
            
        }} catch (e) {{
            console.error(`[-] Failed to hook {target}: ${{e}}`);
        }}
        """
        
        # Add onEnter/onLeave handlers if provided
        if hook.on_enter:
            hook_code += f"\n        // {hook.name} onEnter handler\n"
            hook_code += f"        function {hook.name}_onEnter(context, thisObj, args) {{\n            {hook.on_enter}\n        }}\n"
        
        if hook.on_leave:
            hook_code += f"\n        // {hook.name} onLeave handler\n"
            hook_code += f"        function {hook.name}_onLeave(context, thisObj, args, retval, exception) {{\n            {hook.on_leave}\n        }}\n"
        
        return hook_code
    
    def _generate_native_hook(self, hook: HookConfig) -> str:
        """Generate Frida script for a native function hook."""
        target = hook.target
        
        # Generate hook code
        hook_code = f"""
        // Native hook for {target}
        try {{
            var target = new NativeFunction(
                Module.findExportByName(null, '{target}'),
                'int',
                ['pointer', 'pointer']  // Adjust types as needed
            );
            
            Interceptor.attach(target, {{
                onEnter: function(args) {{
                    this.context = {{
                        timestamp: getCurrentTime(),
                        function: '{target}',
                        args: [],
                        returnAddress: this.returnAddress,
                        thread: Thread.currentThread().toString(),
                        stackTrace: getStackTrace()
                    }};
                    
                    // Process arguments
                    for (var i = 0; i < 8; i++) {{
                        try {{
                            this.context.args[i] = args[i].toInt32();
                        }} catch (e) {{
                            this.context.args[i] = args[i];
                        }}
                    }}
                    
                    // Call onEnter if provided
                    if (typeof {hook.name}_onEnter === 'function') {{
                        try {{
                            this.onEnterResult = {hook.name}_onEnter(this.context, this, args);
                        }} catch (e) {{
                            console.error(`Error in {hook.name}_onEnter: ${{e}}`);
                        }}
                    }}
                }},
                
                onLeave: function(retval) {{
                    // Call onLeave if provided
                    if (typeof {hook.name}_onLeave === 'function') {{
                        try {{
                            this.context.retval = retval.toInt32();
                            this.context.onEnterResult = this.onEnterResult;
                            
                            {hook.name}_onLeave(this.context, this, retval);
                        }} catch (e) {{
                            console.error(`Error in {hook.name}_onLeave: ${{e}}`);
                        }}
                    }}
                }}
            }});
            
            console.log(`[+] Hooked native function {target}`);
            
        }} catch (e) {{
            console.error(`[-] Failed to hook native function {target}: ${{e}}`);
        }}
        """
        
        # Add onEnter/onLeave handlers if provided
        if hook.on_enter:
            hook_code += f"\n        // {hook.name} onEnter handler\n"
            hook_code += f"        function {hook.name}_onEnter(context, thisObj, args) {{\n            {hook.on_enter}\n        }}\n"
        
        if hook.on_leave:
            hook_code += f"\n        // {hook.name} onLeave handler\n"
            hook_code += f"        function {hook.name}_onLeave(context, thisObj, retval) {{\n            {hook.on_leave}\n        }}\n"
        
        return hook_code
    
    def _handle_message(self, message: Dict, data: Any) -> None:
        """Handle messages from the Frida script."""
        try:
            if 'payload' in message:
                payload = message['payload']
                hook_name = payload.get('hook')
                
                # Call the appropriate message handler if registered
                if hook_name in self.message_handlers:
                    self.message_handlers[hook_name](payload, data)
                else:
                    # Default message handling
                    self._process_hook_message(payload, data)
            
        except Exception as e:
            logger.error(f"Error handling message: {str(e)}", exc_info=True)
    
    def _process_hook_message(self, payload: Dict, data: Any) -> None:
        """Process a hook message and generate findings."""
        hook_name = payload.get('hook')
        event_type = payload.get('type')
        context = payload.get('context', {})
        
        # Generate a finding based on the hook and event type
        finding = Finding(
            title=f"Dynamic Analysis: {hook_name} {event_type}",
            description=f"Hook '{hook_name}' triggered with event type '{event_type}'",
            severity=Severity.MEDIUM,  # Default severity
            context={
                "hook": hook_name,
                "event_type": event_type,
                "data": context,
                "timestamp": context.get('timestamp')
            }
        )
        
        self.findings.append(finding)
        logger.debug(f"Hook '{hook_name}' triggered: {event_type}")
    
    # ===== Hook Handlers =====
    
    def _on_ssl_context_get_instance(self, context: Dict, this_obj: Any, args: list) -> Dict:
        """Handler for SSLContext.getInstance calls."""
        protocol = args[0] if args else "unknown"
        
        # Log the SSL/TLS protocol being used
        finding = Finding(
            title="SSL/TLS Protocol Usage",
            description=f"Application is using SSL/TLS protocol: {protocol}",
            severity=Severity.LOW,
            context={
                "protocol": protocol,
                "stack_trace": context.get('stackTrace'),
                "hook": "ssl_verify",
                "event_type": "ssl_context_created"
            }
        )
        
        self.findings.append(finding)
        logger.info(f"SSL/TLS protocol used: {protocol}")
        
        return {"protocol": protocol}
    
    def _on_http_request(self, context: Dict, this_obj: Any, args: list) -> Dict:
        """Handler for URL.openConnection calls."""
        url = str(args[0]) if args else "unknown"
        
        # Check for HTTP (non-HTTPS) URLs
        if url.lower().startswith('http://'):
            finding = Finding(
                title="Insecure HTTP Connection",
                description=f"Application is making an insecure HTTP connection to: {url}",
                severity=Severity.HIGH,
                context={
                    "url": url,
                    "stack_trace": context.get('stackTrace'),
                    "hook": "http_request",
                    "event_type": "insecure_connection"
                }
            )
            
            self.findings.append(finding)
            logger.warning(f"Insecure HTTP connection detected: {url}")
        
        return {"url": url}
    
    def _on_cipher_init(self, context: Dict, this_obj: Any, args: list) -> Dict:
        """Handler for Cipher.getInstance calls."""
        transformation = args[0] if args else "unknown"
        
        # Check for weak cipher transformations
        weak_ciphers = ["DES", "DESede", "RC2", "RC4", "NULL", "Anon", "Export", "DESede/CBC/NoPadding", "DES/CBC/NoPadding"]
        
        for weak_cipher in weak_ciphers:
            if weak_cipher.lower() in transformation.lower():
                finding = Finding(
                    title="Weak Cryptographic Algorithm",
                    description=f"Application is using a potentially weak cipher: {transformation}",
                    severity=Severity.HIGH,
                    context={
                        "transformation": transformation,
                        "weak_cipher": weak_cipher,
                        "stack_trace": context.get('stackTrace'),
                        "hook": "cipher_init",
                        "event_type": "weak_crypto"
                    }
                )
                
                self.findings.append(finding)
                logger.warning(f"Weak cipher detected: {transformation}")
                break
        
        return {"transformation": transformation}
    
    def _on_shared_prefs_put(self, context: Dict, this_obj: Any, args: list) -> Dict:
        """Handler for SharedPreferences.Editor.putString calls."""
        key = args[0] if len(args) > 0 else "unknown"
        value = args[1] if len(args) > 1 else None
        
        # Check for sensitive keys
        sensitive_keys = ["password", "token", "secret", "key", "auth", "credential"]
        
        for sensitive_key in sensitive_keys:
            if sensitive_key.lower() in key.lower():
                # Truncate value for logging
                value_str = str(value)
                truncated_value = value_str[:50] + (value_str[50:] and '...')
                
                finding = Finding(
                    title="Sensitive Data in SharedPreferences",
                    f"Sensitive data found in SharedPreferences with key: {key}",
                    severity=Severity.HIGH,
                    context={
                        "key": key,
                        "value_length": len(str(value)),
                        "value_preview": truncated_value,
                        "stack_trace": context.get('stackTrace'),
                        "hook": "shared_prefs",
                        "event_type": "sensitive_data_storage"
                    }
                )
                
                self.findings.append(finding)
                logger.warning(f"Sensitive data in SharedPreferences - Key: {key}, Value: {truncated_value}")
                break
        
        return {"key": key, "value_length": len(str(value)) if value else 0}
    
    def _on_webview_load_url(self, context: Dict, this_obj: Any, args: list) -> Dict:
        """Handler for WebView.loadUrl calls."""
        url = args[0] if args else "unknown"
        
        # Check for JavaScript execution
        if url.lower().startswith('javascript:'):
            finding = Finding(
                title="JavaScript Execution in WebView",
                description="Application is executing JavaScript in a WebView",
                severity=Severity.MEDIUM,
                context={
                    "url": url,
                    "stack_trace": context.get('stackTrace'),
                    "hook": "webview_load_url",
                    "event_type": "javascript_execution"
                }
            )
            
            self.findings.append(finding)
            logger.info(f"JavaScript execution in WebView: {url}")
        
        return {"url": url}
    
    # iOS-specific handlers
    
    def _on_nsurlsession_ssl(self, context: Dict, this_obj: Any, args: list) -> Dict:
        """Handler for NSURLSession SSL validation."""
        # This would be implemented for iOS to check SSL validation
        return {}
    
    def _on_nsurlconnection_request(self, context: Dict, this_obj: Any, args: list) -> Dict:
        """Handler for NSURLConnection requests."""
        # This would be implemented for iOS to monitor network requests
        return {}
    
    def _on_keychain_add(self, context: Dict, this_obj: Any, args: list) -> Dict:
        """Handler for Keychain item additions."""
        # This would be implemented for iOS to monitor Keychain access
        return {}
    
    def _on_userdefaults_set(self, context: Dict, this_obj: Any, args: list) -> Dict:
        """Handler for NSUserDefaults setObject:forKey: calls."""
        # This would be implemented for iOS to monitor UserDefaults access
        return {}

# Example usage
async def example_usage():
    # Initialize the dynamic analyzer
    analyzer = DynamicAnalyzer(
        platform=Platform.ANDROID,
        package_name="com.example.app"
    )
    
    try:
        # Start the analysis (spawn the app if needed)
        await analyzer.start(spawn=True)
        
        # Let the app run for a while
        await asyncio.sleep(30)
        
        # Get the findings
        for finding in analyzer.findings:
            print(f"[+] {finding.title}: {finding.description}")
        
    finally:
        # Stop the analysis
        await analyzer.stop()

if __name__ == "__main__":
    asyncio.run(example_usage())

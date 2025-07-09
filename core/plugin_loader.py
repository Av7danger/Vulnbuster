"""
Plugin Submission API
Dynamic plugin system for loading external modules
"""

import asyncio
import logging
import importlib.util
import inspect
import sys
from typing import Dict, Any, List, Optional, Callable
from pathlib import Path
from datetime import datetime
import json
import traceback

class PluginLoader:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.plugins_dir = Path("plugins")
        self.plugins_dir.mkdir(exist_ok=True)
        self.loaded_plugins = {}
        self.plugin_results = []
        self.plugin_log_file = Path("logs/plugin_executions.json")
        self.plugin_log_file.parent.mkdir(exist_ok=True)
        
        # Required plugin interface
        self.required_methods = ['run', 'get_info', 'get_requirements']
        
        # Plugin validation rules
        self.validation_rules = {
            'max_execution_time': 30,  # seconds
            'allowed_modules': [
                'httpx', 'requests', 'json', 're', 'base64', 'hashlib',
                'urllib', 'pathlib', 'datetime', 'asyncio', 'logging'
            ],
            'forbidden_keywords': [
                'eval', 'exec', 'compile', 'open', 'file', '__import__',
                'globals', 'locals', 'vars', 'dir', 'type', 'super'
            ]
        }
    
    def scan_plugins(self) -> List[str]:
        """Scan plugins directory for available plugins"""
        plugins = []
        
        try:
            for plugin_file in self.plugins_dir.glob("*.py"):
                if plugin_file.name != "__init__.py":
                    plugins.append(plugin_file.name)
            
            logging.info(f"Found {len(plugins)} plugins: {plugins}")
            return plugins
            
        except Exception as e:
            logging.error(f"Failed to scan plugins: {e}")
            return []
    
    def load_plugin(self, plugin_name: str) -> Optional[Dict[str, Any]]:
        """Load a plugin from file"""
        try:
            plugin_path = self.plugins_dir / plugin_name
            
            if not plugin_path.exists():
                logging.error(f"Plugin not found: {plugin_name}")
                return None
            
            # Load plugin module
            spec = importlib.util.spec_from_file_location(plugin_name, plugin_path)
            if spec is None or spec.loader is None:
                logging.error(f"Failed to load plugin spec: {plugin_name}")
                return None
            
            module = importlib.util.module_from_spec(spec)
            
            # Validate plugin before execution
            if not self._validate_plugin(module, plugin_name):
                logging.error(f"Plugin validation failed: {plugin_name}")
                return None
            
            # Execute module
            spec.loader.exec_module(module)
            
            # Verify required methods exist
            if not self._verify_plugin_interface(module):
                logging.error(f"Plugin interface verification failed: {plugin_name}")
                return None
            
            # Get plugin info
            plugin_info = module.get_info()
            
            plugin_data = {
                'name': plugin_name,
                'module': module,
                'info': plugin_info,
                'loaded_at': datetime.now().isoformat(),
                'path': str(plugin_path)
            }
            
            self.loaded_plugins[plugin_name] = plugin_data
            logging.info(f"Plugin loaded successfully: {plugin_name}")
            
            return plugin_data
            
        except Exception as e:
            logging.error(f"Failed to load plugin {plugin_name}: {e}")
            return None
    
    def _validate_plugin(self, module, plugin_name: str) -> bool:
        """Validate plugin code for security"""
        try:
            # Read plugin source code
            plugin_path = self.plugins_dir / plugin_name
            with open(plugin_path, 'r', encoding='utf-8') as f:
                source_code = f.read()
            
            # Check for forbidden keywords
            for keyword in self.validation_rules['forbidden_keywords']:
                if keyword in source_code:
                    logging.warning(f"Plugin {plugin_name} contains forbidden keyword: {keyword}")
                    return False
            
            # Check for suspicious patterns
            suspicious_patterns = [
                'import os', 'import subprocess', 'import sys',
                'os.system', 'subprocess.call', 'subprocess.Popen'
            ]
            
            for pattern in suspicious_patterns:
                if pattern in source_code:
                    logging.warning(f"Plugin {plugin_name} contains suspicious pattern: {pattern}")
                    return False
            
            return True
            
        except Exception as e:
            logging.error(f"Plugin validation error: {e}")
            return False
    
    def _verify_plugin_interface(self, module) -> bool:
        """Verify plugin has required methods"""
        try:
            for method in self.required_methods:
                if not hasattr(module, method) or not callable(getattr(module, method)):
                    logging.error(f"Plugin missing required method: {method}")
                    return False
            
            return True
            
        except Exception as e:
            logging.error(f"Interface verification error: {e}")
            return False
    
    async def execute_plugin(self, plugin_name: str, target: str, headers: Dict[str, str] = None, 
                           context: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """Execute a loaded plugin"""
        try:
            if plugin_name not in self.loaded_plugins:
                logging.error(f"Plugin not loaded: {plugin_name}")
                return None
            
            plugin_data = self.loaded_plugins[plugin_name]
            module = plugin_data['module']
            
            # Prepare execution context
            exec_context = {
                'target': target,
                'headers': headers or {},
                'context': context or {},
                'timestamp': datetime.now().isoformat()
            }
            
            # Execute plugin with timeout
            try:
                if asyncio.iscoroutinefunction(module.run):
                    result = await asyncio.wait_for(
                        module.run(target, headers, context),
                        timeout=self.validation_rules['max_execution_time']
                    )
                else:
                    # Run sync function in executor
                    loop = asyncio.get_event_loop()
                    result = await loop.run_in_executor(
                        None,
                        lambda: module.run(target, headers, context)
                    )
                
                # Log execution result
                execution_log = {
                    'plugin_name': plugin_name,
                    'target': target,
                    'execution_time': datetime.now().isoformat(),
                    'result': result,
                    'status': 'success'
                }
                
                self.plugin_results.append(execution_log)
                self._log_plugin_execution(execution_log)
                
                logging.info(f"Plugin {plugin_name} executed successfully")
                return result
                
            except asyncio.TimeoutError:
                logging.error(f"Plugin {plugin_name} execution timed out")
                return None
                
        except Exception as e:
            logging.error(f"Plugin execution failed {plugin_name}: {e}")
            
            # Log error
            error_log = {
                'plugin_name': plugin_name,
                'target': target,
                'execution_time': datetime.now().isoformat(),
                'error': str(e),
                'traceback': traceback.format_exc(),
                'status': 'error'
            }
            
            self.plugin_results.append(error_log)
            self._log_plugin_execution(error_log)
            
            return None
    
    def _log_plugin_execution(self, execution_log: Dict[str, Any]):
        """Log plugin execution to file"""
        try:
            # Load existing logs
            existing_logs = []
            if self.plugin_log_file.exists():
                with open(self.plugin_log_file, 'r') as f:
                    existing_logs = json.load(f)
            
            # Add new log
            existing_logs.append(execution_log)
            
            # Save updated logs
            with open(self.plugin_log_file, 'w') as f:
                json.dump(existing_logs, f, indent=2)
                
        except Exception as e:
            logging.error(f"Failed to log plugin execution: {e}")
    
    def get_loaded_plugins(self) -> List[Dict[str, Any]]:
        """Get list of loaded plugins"""
        return [
            {
                'name': name,
                'info': data['info'],
                'loaded_at': data['loaded_at'],
                'path': data['path']
            }
            for name, data in self.loaded_plugins.items()
        ]
    
    def unload_plugin(self, plugin_name: str) -> bool:
        """Unload a plugin"""
        try:
            if plugin_name in self.loaded_plugins:
                del self.loaded_plugins[plugin_name]
                logging.info(f"Plugin unloaded: {plugin_name}")
                return True
            else:
                logging.warning(f"Plugin not found for unloading: {plugin_name}")
                return False
                
        except Exception as e:
            logging.error(f"Failed to unload plugin {plugin_name}: {e}")
            return False
    
    def reload_plugin(self, plugin_name: str) -> bool:
        """Reload a plugin"""
        try:
            # Unload first
            self.unload_plugin(plugin_name)
            
            # Load again
            plugin_data = self.load_plugin(plugin_name)
            return plugin_data is not None
            
        except Exception as e:
            logging.error(f"Failed to reload plugin {plugin_name}: {e}")
            return False
    
    def get_plugin_statistics(self) -> Dict[str, Any]:
        """Get plugin execution statistics"""
        successful_executions = len([r for r in self.plugin_results if r.get('status') == 'success'])
        failed_executions = len([r for r in self.plugin_results if r.get('status') == 'error'])
        
        return {
            'total_plugins_loaded': len(self.loaded_plugins),
            'total_executions': len(self.plugin_results),
            'successful_executions': successful_executions,
            'failed_executions': failed_executions,
            'success_rate': successful_executions / len(self.plugin_results) if self.plugin_results else 0,
            'loaded_plugins': list(self.loaded_plugins.keys()),
            'recent_executions': self.plugin_results[-10:] if self.plugin_results else []
        }
    
    def create_plugin_template(self, plugin_name: str) -> bool:
        """Create a plugin template file"""
        try:
            template_content = f'''"""
{plugin_name} - VulnBuster Plugin Template
Custom vulnerability scanner plugin
"""

import asyncio
import logging
from typing import Dict, Any, Optional

def get_info() -> Dict[str, Any]:
    """Return plugin information"""
    return {{
        'name': '{plugin_name}',
        'version': '1.0.0',
        'description': 'Custom vulnerability scanner plugin',
        'author': 'Your Name',
        'category': 'custom',
        'tags': ['custom', 'vulnerability']
    }}

def get_requirements() -> Dict[str, Any]:
    """Return plugin requirements"""
    return {{
        'python_version': '>=3.8',
        'dependencies': [],
        'permissions': ['network_access']
    }}

async def run(target: str, headers: Dict[str, str] = None, context: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Main plugin execution function
    
    Args:
        target: Target URL or host
        headers: HTTP headers to use
        context: Additional context data
    
    Returns:
        Dict containing scan results
    """
    try:
        logging.info(f"Running {{get_info()['name']}} against {{target}}")
        
        # Your plugin logic here
        result = {{
            'plugin': get_info()['name'],
            'target': target,
            'status': 'completed',
            'findings': [],
            'timestamp': asyncio.get_event_loop().time()
        }}
        
        # Example: Add your vulnerability detection logic
        # findings = await detect_vulnerabilities(target, headers)
        # result['findings'] = findings
        
        logging.info(f"{{get_info()['name']}} completed successfully")
        return result
        
    except Exception as e:
        logging.error(f"{{get_info()['name']}} failed: {{e}}")
        return {{
            'plugin': get_info()['name'],
            'target': target,
            'status': 'error',
            'error': str(e),
            'timestamp': asyncio.get_event_loop().time()
        }}

# Example helper functions
async def detect_vulnerabilities(target: str, headers: Dict[str, str] = None) -> list:
    """Detect vulnerabilities in target"""
    findings = []
    
    # Add your vulnerability detection logic here
    
    return findings
'''
            
            template_path = self.plugins_dir / f"{plugin_name}.py"
            
            if template_path.exists():
                logging.warning(f"Plugin template already exists: {plugin_name}")
                return False
            
            with open(template_path, 'w') as f:
                f.write(template_content)
            
            logging.info(f"Plugin template created: {template_path}")
            return True
            
        except Exception as e:
            logging.error(f"Failed to create plugin template: {e}")
            return False 
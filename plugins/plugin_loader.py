import os
import sys
import importlib
import importlib.util
import logging
import json
from pathlib import Path

class PluginLoader:
    def __init__(self, plugin_dir='plugins'):
        self.plugin_dir = Path(plugin_dir)
        self.plugins = {}
        self.loaded_plugins = {}

    def discover_plugins(self):
        """Discover available plugins in the plugin directory"""
        try:
            if not self.plugin_dir.exists():
                logging.warning(f"Plugin directory {self.plugin_dir} does not exist")
                return []

            plugins = []
            for plugin_file in self.plugin_dir.glob('*.py'):
                if plugin_file.name.startswith('__'):
                    continue
                
                plugin_name = plugin_file.stem
                plugin_info = {
                    'name': plugin_name,
                    'file': str(plugin_file),
                    'path': plugin_file
                }
                
                # Try to get plugin metadata
                try:
                    spec = importlib.util.spec_from_file_location(plugin_name, plugin_file)
                    if spec is not None and spec.loader is not None:
                        module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(module)
                        
                        if hasattr(module, 'PLUGIN_INFO'):
                            plugin_info.update(module.PLUGIN_INFO)
                        
                        if hasattr(module, 'Plugin'):
                            plugin_info['class'] = module.Plugin
                    
                except Exception as e:
                    logging.warning(f"Failed to load plugin {plugin_name}: {e}")
                    continue
                
                plugins.append(plugin_info)
                self.plugins[plugin_name] = plugin_info
            
            logging.info(f"Discovered {len(plugins)} plugins")
            return plugins
            
        except Exception as e:
            logging.error(f"Error discovering plugins: {e}")
            return []

    def load_plugin(self, plugin_name):
        """Load a specific plugin"""
        try:
            if plugin_name not in self.plugins:
                logging.error(f"Plugin {plugin_name} not found")
                return None
            
            plugin_info = self.plugins[plugin_name]
            plugin_file = plugin_info['file']
            
            # Load plugin module
            spec = importlib.util.spec_from_file_location(plugin_name, plugin_file)
            if spec is None or spec.loader is None:
                logging.error(f"Failed to create spec for plugin {plugin_name}")
                return None
                
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Get plugin class
            if hasattr(module, 'Plugin'):
                plugin_class = module.Plugin
                plugin_instance = plugin_class()
                
                self.loaded_plugins[plugin_name] = {
                    'instance': plugin_instance,
                    'info': plugin_info,
                    'module': module
                }
                
                logging.info(f"Loaded plugin: {plugin_name}")
                return plugin_instance
            else:
                logging.error(f"Plugin {plugin_name} does not have a Plugin class")
                return None
                
        except Exception as e:
            logging.error(f"Failed to load plugin {plugin_name}: {e}")
            return None

    def load_all_plugins(self):
        """Load all discovered plugins"""
        loaded = []
        for plugin_name in self.plugins:
            plugin_instance = self.load_plugin(plugin_name)
            if plugin_instance:
                loaded.append(plugin_instance)
        return loaded

    def get_plugin(self, plugin_name):
        """Get a loaded plugin instance"""
        if plugin_name in self.loaded_plugins:
            return self.loaded_plugins[plugin_name]['instance']
        return None

    def get_plugin_info(self, plugin_name):
        """Get plugin information"""
        if plugin_name in self.plugins:
            return self.plugins[plugin_name]
        return None

    def list_plugins(self):
        """List all available plugins"""
        return list(self.plugins.keys())

    def list_loaded_plugins(self):
        """List all loaded plugins"""
        return list(self.loaded_plugins.keys())

    def unload_plugin(self, plugin_name):
        """Unload a plugin"""
        if plugin_name in self.loaded_plugins:
            del self.loaded_plugins[plugin_name]
            logging.info(f"Unloaded plugin: {plugin_name}")
            return True
        return False

    def reload_plugin(self, plugin_name):
        """Reload a plugin"""
        self.unload_plugin(plugin_name)
        return self.load_plugin(plugin_name)

    def execute_plugin(self, plugin_name, *args, **kwargs):
        """Execute a plugin with given arguments"""
        plugin_instance = self.get_plugin(plugin_name)
        if plugin_instance and hasattr(plugin_instance, 'run'):
            try:
                return plugin_instance.run(*args, **kwargs)
            except Exception as e:
                logging.error(f"Error executing plugin {plugin_name}: {e}")
                return None
        else:
            logging.error(f"Plugin {plugin_name} not loaded or does not have run method")
            return None

    def save_plugin_config(self, filename='plugin_config.json'):
        """Save plugin configuration"""
        config = {
            'plugins': self.plugins,
            'loaded_plugins': list(self.loaded_plugins.keys())
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(config, f, indent=2)
            logging.info(f"Plugin configuration saved to {filename}")
        except Exception as e:
            logging.error(f"Failed to save plugin configuration: {e}")

    def load_plugin_config(self, filename='plugin_config.json'):
        """Load plugin configuration"""
        try:
            with open(filename, 'r') as f:
                config = json.load(f)
            
            # Load plugins from config
            for plugin_name in config.get('loaded_plugins', []):
                self.load_plugin(plugin_name)
            
            logging.info(f"Plugin configuration loaded from {filename}")
        except Exception as e:
            logging.error(f"Failed to load plugin configuration: {e}") 
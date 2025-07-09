import asyncio
import logging
import importlib.util
import os
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse

class Scanner:
    def __init__(self, payload_engine, analyzer, threads=10, timeout=10, verbose=False):
        self.payload_engine = payload_engine
        self.analyzer = analyzer
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.findings = []
        self.modules = {}
        self.session_manager = None

    def set_session_manager(self, session_manager):
        """Set session manager for authenticated scans"""
        self.session_manager = session_manager

    async def load_modules(self, module_names: List[str]) -> Dict[str, Any]:
        """Dynamically load vulnerability modules"""
        modules = {}
        modules_path = os.path.join(os.path.dirname(__file__), '..', 'modules')
        
        for module_name in module_names:
            try:
                # Import module dynamically
                module_path = os.path.join(modules_path, f"{module_name}.py")
                if os.path.exists(module_path):
                    spec = importlib.util.spec_from_file_location(module_name, module_path)
                    if spec is not None and spec.loader is not None:
                        module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(module)
                        
                        if hasattr(module, 'Module'):
                            modules[module_name] = module.Module
                            logging.info(f"Loaded module: {module_name}")
                        else:
                            logging.warning(f"Module {module_name} does not have Module class")
                    else:
                        logging.warning(f"Failed to create spec for module {module_name}")
                else:
                    logging.warning(f"Module file not found: {module_path}")
            except Exception as e:
                logging.error(f"Failed to load module {module_name}: {e}")
        
        return modules

    async def scan_url(self, url: str, modules: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan a single URL with all loaded modules"""
        url_findings = []
        
        # Create semaphore for concurrent requests
        semaphore = asyncio.Semaphore(self.threads)
        
        async def scan_with_module(module_name, module_class):
            async with semaphore:
                try:
                    module_instance = module_class(
                        url=url,
                        payload_engine=self.payload_engine,
                        analyzer=self.analyzer,
                        verbose=self.verbose
                    )
                    
                    if hasattr(module_instance, 'run'):
                        findings = await module_instance.run()
                        if findings:
                            url_findings.extend(findings)
                            logging.info(f"Module {module_name} found {len(findings)} vulnerabilities")
                    
                except Exception as e:
                    logging.error(f"Error in module {module_name}: {e}")
        
        # Run all modules concurrently
        tasks = []
        for module_name, module_class in modules.items():
            task = asyncio.create_task(scan_with_module(module_name, module_class))
            tasks.append(task)
        
        # Wait for all modules to complete
        await asyncio.gather(*tasks, return_exceptions=True)
        
        return url_findings

    async def scan(self, urls: List[str], module_names: List[str]) -> List[Dict[str, Any]]:
        """Main scanning method"""
        logging.info(f"Starting scan of {len(urls)} URLs with modules: {module_names}")
        
        # Load modules
        self.modules = await self.load_modules(module_names)
        if not self.modules:
            logging.error("No modules loaded. Exiting.")
            return []
        
        # Scan each URL
        all_findings = []
        for url in urls:
            logging.info(f"Scanning URL: {url}")
            findings = await self.scan_url(url, self.modules)
            all_findings.extend(findings)
        
        # Analyze findings
        if self.analyzer:
            all_findings = await self.analyzer.analyze_findings(all_findings)
        
        logging.info(f"Scan completed. Found {len(all_findings)} vulnerabilities")
        return all_findings

    async def run_scan(self, urls: List[str], module_names: List[str]) -> List[Dict[str, Any]]:
        """Alias for scan method for compatibility"""
        return await self.scan(urls, module_names)

    def get_scan_summary(self) -> Dict[str, Any]:
        """Get summary of scan results"""
        if not self.findings:
            return {"total": 0, "by_risk": {}, "by_module": {}}
        
        summary = {
            "total": len(self.findings),
            "by_risk": {},
            "by_module": {}
        }
        
        for finding in self.findings:
            # Count by risk level
            risk = finding.get('risk', 'unknown')
            summary['by_risk'][risk] = summary['by_risk'].get(risk, 0) + 1
            
            # Count by module type
            vuln_type = finding.get('type', 'unknown')
            summary['by_module'][vuln_type] = summary['by_module'].get(vuln_type, 0) + 1
        
        return summary 
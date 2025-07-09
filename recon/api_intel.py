import asyncio
import aiohttp
from typing import Dict, Any, List, Optional
import json
from core.ai import ask_mixtral

# --- API Intelligence Module ---
class APIIntelligence:
    def __init__(self, shodan_key: str = None, censys_creds: Dict[str, str] = None, dnsdb_key: str = None):
        self.shodan_key = shodan_key
        self.censys_creds = censys_creds
        self.dnsdb_key = dnsdb_key
        self.enrichment_data = {}
    
    async def shodan_lookup(self, target: str) -> Dict[str, Any]:
        """Query Shodan for host information"""
        if not self.shodan_key:
            return {'error': 'Shodan API key not provided'}
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://api.shodan.io/shodan/host/{target}?key={self.shodan_key}"
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return {
                            'ip': data.get('ip_str'),
                            'ports': data.get('ports', []),
                            'hostnames': data.get('hostnames', []),
                            'os': data.get('os'),
                            'org': data.get('org'),
                            'data': data.get('data', [])
                        }
                    else:
                        return {'error': f'Shodan API error: {resp.status}'}
        except Exception as e:
            return {'error': f'Shodan lookup failed: {e}'}
    
    async def censys_lookup(self, target: str) -> Dict[str, Any]:
        """Query Censys for host information"""
        if not self.censys_creds:
            return {'error': 'Censys credentials not provided'}
        
        try:
            auth = aiohttp.BasicAuth(
                login=self.censys_creds.get('api_id'),
                password=self.censys_creds.get('api_secret')
            )
            
            async with aiohttp.ClientSession(auth=auth) as session:
                url = f"https://search.censys.io/api/v2/hosts/{target}"
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return {
                            'ip': data.get('ip'),
                            'ports': list(data.get('ports', [])),
                            'services': data.get('services', []),
                            'location': data.get('location'),
                            'autonomous_system': data.get('autonomous_system')
                        }
                    else:
                        return {'error': f'Censys API error: {resp.status}'}
        except Exception as e:
            return {'error': f'Censys lookup failed: {e}'}
    
    async def dnsdb_lookup(self, domain: str) -> Dict[str, Any]:
        """Query DNSDB for DNS history"""
        if not self.dnsdb_key:
            return {'error': 'DNSDB API key not provided'}
        
        try:
            headers = {'X-API-Key': self.dnsdb_key}
            async with aiohttp.ClientSession() as session:
                url = f"https://api.dnsdb.info/lookup/rrset/name/{domain}"
                async with session.get(url, headers=headers) as resp:
                    if resp.status == 200:
                        data = await resp.text()
                        records = [line.strip() for line in data.split('\n') if line.strip()]
                        return {
                            'domain': domain,
                            'records': records,
                            'record_count': len(records)
                        }
                    else:
                        return {'error': f'DNSDB API error: {resp.status}'}
        except Exception as e:
            return {'error': f'DNSDB lookup failed: {e}'}
    
    async def enrich_host(self, target: str) -> Dict[str, Any]:
        """Enrich host with all available API data"""
        enrichment = {
            'target': target,
            'shodan': await self.shodan_lookup(target),
            'censys': await self.censys_lookup(target),
            'dnsdb': await self.dnsdb_lookup(target) if '.' in target else {'error': 'Not a domain'}
        }
        
        self.enrichment_data[target] = enrichment
        return enrichment
    
    async def ai_analyze_enrichment(self, enrichment: Dict[str, Any]) -> str:
        """Use AI to analyze enrichment data and suggest vulnerabilities"""
        prompt = f"""
        Analyze this host enrichment data and suggest potential vulnerabilities and attack vectors:
        
        Target: {enrichment.get('target')}
        Shodan: {json.dumps(enrichment.get('shodan', {}), indent=2)}
        Censys: {json.dumps(enrichment.get('censys', {}), indent=2)}
        DNSDB: {json.dumps(enrichment.get('dnsdb', {}), indent=2)}
        
        Suggest:
        1. Most likely vulnerabilities based on open ports/services
        2. Attack vectors and exploitation priority
        3. Specific tools/techniques to use
        """
        
        try:
            analysis = await ask_mixtral(prompt)
            return analysis
        except Exception as e:
            return f"[AI Analysis Error] {e}"
    
    async def save_enrichment(self, output_path: str = 'reports/api_enrichment.json'):
        """Save enrichment data to JSON file"""
        from pathlib import Path
        
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(self.enrichment_data, f, indent=2)
        
        return output_path 
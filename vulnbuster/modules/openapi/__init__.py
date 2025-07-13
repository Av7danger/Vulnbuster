"""
OpenAPI/Swagger Parser Module

This module provides functionality to parse OpenAPI/Swagger specifications,
discover API endpoints, and generate test cases for security testing.
"""

import re
import json
import yaml
import random
import string
import asyncio
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union, Tuple, Set
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs, urlencode

import aiohttp
from faker import Faker

class HTTPMethod(Enum):
    """HTTP methods supported by OpenAPI."""
    GET = "get"
    POST = "post"
    PUT = "put"
    DELETE = "delete"
    PATCH = "patch"
    HEAD = "head"
    OPTIONS = "options"
    TRACE = "trace"

class ParameterLocation(Enum):
    """Location of API parameters."""
    QUERY = "query"
    HEADER = "header"
    PATH = "path"
    COOKIE = "cookie"
    BODY = "body"

class SecuritySchemeType(Enum):
    """Types of security schemes in OpenAPI."""
    API_KEY = "apiKey"
    HTTP = "http"
    OAUTH2 = "oauth2"
    OPEN_ID_CONNECT = "openIdConnect"

@dataclass
class SecurityRequirement:
    """Represents a security requirement for an API operation."""
    name: str
    scopes: List[str] = field(default_factory=list)
    type: SecuritySchemeType = SecuritySchemeType.API_KEY
    location: ParameterLocation = ParameterLocation.HEADER
    scheme: str = ""

@dataclass
class APIParameter:
    """Represents an API parameter."""
    name: str
    location: ParameterLocation
    required: bool = False
    schema: Dict = field(default_factory=dict)
    description: str = ""
    example: Any = None

@dataclass
class APIRequest:
    """Represents an API request."""
    method: HTTPMethod
    path: str
    base_url: str = ""
    path_parameters: List[APIParameter] = field(default_factory=list)
    query_parameters: List[APIParameter] = field(default_factory=list)
    header_parameters: List[APIParameter] = field(default_factory=list)
    cookie_parameters: List[APIParameter] = field(default_factory=list)
    body_parameters: List[APIParameter] = field(default_factory=list)
    security: List[SecurityRequirement] = field(default_factory=list)
    consumes: List[str] = field(default_factory=list)
    produces: List[str] = field(default_factory=list)
    deprecated: bool = False
    operation_id: str = ""
    summary: str = ""
    description: str = ""
    
    @property
    def url(self) -> str:
        """Get the full URL for this request."""
        # Handle path parameters
        path = self.path
        for param in self.path_parameters:
            if param.required:
                path = path.replace(f"{{{param.name}}}", self._generate_value(param))
        
        # Handle query parameters
        query_params = {}
        for param in self.query_parameters:
            if param.required or random.random() > 0.5:  # 50% chance to include optional params
                query_params[param.name] = self._generate_value(param)
        
        # Build URL
        url_parts = list(urlparse(urljoin(self.base_url, path)))
        if query_params:
            url_parts[4] = urlencode(query_params, doseq=True)
        
        return urlunparse(url_parts)
    
    def _generate_value(self, param: APIParameter) -> str:
        """Generate a value for a parameter based on its schema."""
        # Use example if provided
        if param.example is not None:
            return str(param.example)
        
        # Generate based on schema
        schema = param.schema or {}
        param_type = schema.get("type", "string")
        
        if param_type == "string":
            if "enum" in schema:
                return random.choice(schema["enum"])
            if "format" in schema:
                if schema["format"] == "email":
                    return Faker().email()
                elif schema["format"] == "date-time":
                    return Faker().iso8601()
                elif schema["format"] == "uuid":
                    return Faker().uuid4()
                elif schema["format"] == "ipv4":
                    return Faker().ipv4()
                elif schema["format"] == "ipv6":
                    return Faker().ipv6()
            
            # Generate a random string
            min_length = max(schema.get("minLength", 3), 1)
            max_length = min(schema.get("maxLength", 20), 1000)
            length = random.randint(min_length, max_length)
            return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        
        elif param_type == "integer" or param_type == "number":
            minimum = schema.get("minimum", 0)
            maximum = schema.get("maximum", 100)
            return str(random.randint(minimum, maximum))
        
        elif param_type == "boolean":
            return random.choice(["true", "false"])
        
        elif param_type == "array":
            items = schema.get("items", {})
            item_type = items.get("type", "string")
            count = min(schema.get("maxItems", 3), 10)  # Limit array size
            
            if item_type == "string":
                return ",".join([self._generate_value(APIParameter("", ParameterLocation.QUERY, schema=items)) 
                               for _ in range(count)])
            else:
                return str([self._generate_value(APIParameter("", ParameterLocation.QUERY, schema=items)) 
                          for _ in range(count)])
        
        # Default fallback
        return "test_value"
    
    def get_headers(self) -> Dict[str, str]:
        """Get headers for this request."""
        headers = {}
        
        # Add content-type if there's a body
        if self.body_parameters and "application/json" in self.consumes:
            headers["Content-Type"] = "application/json"
        
        # Add header parameters
        for param in self.header_parameters:
            if param.required or random.random() > 0.5:  # 50% chance to include optional params
                headers[param.name] = self._generate_value(param)
        
        return headers
    
    def get_cookies(self) -> Dict[str, str]:
        """Get cookies for this request."""
        cookies = {}
        for param in self.cookie_parameters:
            if param.required or random.random() > 0.5:  # 50% chance to include optional params
                cookies[param.name] = self._generate_value(param)
        return cookies
    
    def get_body(self) -> Optional[Union[Dict, str]]:
        """Get the request body."""
        if not self.body_parameters:
            return None
        
        # For JSON body, create an object with all parameters
        if "application/json" in self.consumes:
            body = {}
            for param in self.body_parameters:
                if param.required or random.random() > 0.5:  # 50% chance to include optional params
                    # Handle nested properties
                    if "." in param.name:
                        current = body
                        parts = param.name.split(".")
                        for part in parts[:-1]:
                            if part not in current:
                                current[part] = {}
                            current = current[part]
                        current[parts[-1]] = self._generate_value(param)
                    else:
                        body[param.name] = self._generate_value(param)
            return body
        
        # For form data, create URL-encoded form data
        elif "application/x-www-form-urlencoded" in self.consumes:
            form_data = {}
            for param in self.body_parameters:
                if param.required or random.random() > 0.5:  # 50% chance to include optional params
                    form_data[param.name] = self._generate_value(param)
            return urlencode(form_data)
        
        # For other content types, just join parameters with newlines
        else:
            return "\n".join(f"{param.name}={self._generate_value(param)}" 
                             for param in self.body_parameters 
                             if param.required or random.random() > 0.5)

@dataclass
class TestCase:
    """Represents a test case for an API endpoint."""
    request: APIRequest
    expected_status_codes: List[int] = field(default_factory=lambda: [200, 201, 202])
    description: str = ""
    tags: List[str] = field(default_factory=list)
    security_requirements: List[SecurityRequirement] = field(default_factory=list)

class OpenAPIParser:
    """Parser for OpenAPI/Swagger specifications."""
    
    def __init__(self, spec: Union[str, Dict], base_url: str = ""):
        """Initialize the OpenAPI parser.
        
        Args:
            spec: The OpenAPI specification (URL, file path, or dict)
            base_url: Base URL for the API (overrides servers/host if provided)
        """
        self.spec = spec
        self.base_url = base_url.rstrip("/") if base_url else ""
        self.parsed_spec: Dict = {}
        self.requests: List[APIRequest] = []
        self.security_schemes: Dict[str, Dict] = {}
        self.faker = Faker()
    
    async def load(self) -> bool:
        """Load and parse the OpenAPI specification.
        
        Returns:
            bool: True if the spec was loaded successfully, False otherwise
        """
        try:
            # If spec is a dictionary, use it directly
            if isinstance(self.spec, dict):
                self.parsed_spec = self.spec
            # If spec is a URL, fetch it
            elif isinstance(self.spec, str) and self.spec.startswith(('http://', 'https://')):
                async with aiohttp.ClientSession() as session:
                    async with session.get(self.spec) as response:
                        content = await response.text()
                        if self.spec.endswith(('.yaml', '.yml')):
                            self.parsed_spec = yaml.safe_load(content)
                        else:  # Assume JSON
                            self.parsed_spec = json.loads(content)
            # If spec is a file path, read it
            else:
                with open(self.spec, 'r', encoding='utf-8') as f:
                    if self.spec.endswith(('.yaml', '.yml')):
                        self.parsed_spec = yaml.safe_load(f)
                    else:  # Assume JSON
                        self.parsed_spec = json.load(f)
            
            # Extract security schemes
            self.security_schemes = self.parsed_spec.get("components", {}).get("securitySchemes", {})
            
            # Set base URL if not provided
            if not self.base_url and "servers" in self.parsed_spec and self.parsed_spec["servers"]:
                self.base_url = self.parsed_spec["servers"[0]["url"]]
            
            # Parse all paths and operations
            self._parse_paths()
            
            return True
            
        except Exception as e:
            print(f"Error loading OpenAPI spec: {e}")
            return False
    
    def _parse_paths(self) -> None:
        """Parse all paths and operations from the OpenAPI spec."""
        if "paths" not in self.parsed_spec:
            return
        
        for path, path_item in self.parsed_spec["paths"].items():
            for method, operation in path_item.items():
                if method.lower() in [m.value for m in HTTPMethod]:
                    self.requests.append(self._parse_operation(path, method, operation))
    
    def _parse_operation(self, path: str, method: str, operation: Dict) -> APIRequest:
        """Parse a single operation from the OpenAPI spec."""
        # Create base request
        request = APIRequest(
            method=HTTPMethod(method.lower()),
            path=path,
            base_url=self.base_url,
            operation_id=operation.get("operationId", ""),
            summary=operation.get("summary", ""),
            description=operation.get("description", ""),
            deprecated=operation.get("deprecated", False),
            consumes=operation.get("consumes", ["application/json"]),
            produces=operation.get("produces", ["application/json"])
        )
        
        # Parse parameters
        for param in operation.get("parameters", []):
            self._parse_parameter(param, request)
        
        # Parse request body
        if "requestBody" in operation:
            self._parse_request_body(operation["requestBody"], request)
        
        # Parse security requirements
        if "security" in operation:
            request.security = self._parse_security_requirements(operation["security"])
        elif "security" in self.parsed_spec:
            request.security = self._parse_security_requirements(self.parsed_spec["security"])
        
        return request
    
    def _parse_parameter(self, param: Dict, request: APIRequest) -> None:
        """Parse a parameter and add it to the appropriate list in the request."""
        param_obj = APIParameter(
            name=param["name"],
            location=ParameterLocation(param["in"].lower()),
            required=param.get("required", False),
            schema=param.get("schema", {}),
            description=param.get("description", ""),
            example=param.get("example")
        )
        
        # Add to the appropriate parameter list
        if param["in"].lower() == "query":
            request.query_parameters.append(param_obj)
        elif param["in"].lower() == "header":
            request.header_parameters.append(param_obj)
        elif param["in"].lower() == "path":
            request.path_parameters.append(param_obj)
        elif param["in"].lower() == "cookie":
            request.cookie_parameters.append(param_obj)
    
    def _parse_request_body(self, request_body: Dict, request: APIRequest) -> None:
        """Parse a request body and add it to the request."""
        if "content" in request_body:
            for content_type, media_type in request_body["content"].items():
                if content_type == "application/json":
                    schema = media_type.get("schema", {})
                    if "properties" in schema:
                        for prop_name, prop_schema in schema["properties"].items():
                            param = APIParameter(
                                name=prop_name,
                                location=ParameterLocation.BODY,
                                required=prop_name in schema.get("required", []),
                                schema=prop_schema,
                                description=prop_schema.get("description", ""),
                                example=prop_schema.get("example")
                            )
                            request.body_parameters.append(param)
                    elif "$ref" in schema:
                        # Handle $ref to a component schema
                        ref = schema["$ref"].split("/")[-1]
                        if "components" in self.parsed_spec and "schemas" in self.parsed_spec["components"]:
                            if ref in self.parsed_spec["components"]["schemas"]:
                                schema_def = self.parsed_spec["components"]["schemas"][ref]
                                if "properties" in schema_def:
                                    for prop_name, prop_schema in schema_def["properties"].items():
                                        param = APIParameter(
                                            name=prop_name,
                                            location=ParameterLocation.BODY,
                                            required=prop_name in schema_def.get("required", []),
                                            schema=prop_schema,
                                            description=prop_schema.get("description", ""),
                                            example=prop_schema.get("example")
                                        )
                                        request.body_parameters.append(param)
    
    def _parse_security_requirements(self, security: List[Dict]) -> List[SecurityRequirement]:
        """Parse security requirements from the OpenAPI spec."""
        requirements = []
        
        for req in security:
            for scheme_name, scopes in req.items():
                if scheme_name in self.security_schemes:
                    scheme = self.security_schemes[scheme_name]
                    requirements.append(SecurityRequirement(
                        name=scheme_name,
                        scopes=scopes,
                        type=SecuritySchemeType(scheme.get("type")),
                        location=ParameterLocation(scheme.get("in", "header")),
                        scheme=scheme.get("scheme", "")
                    ))
        
        return requirements
    
    def generate_test_cases(self, include_optional: bool = True) -> List[TestCase]:
        """Generate test cases for all API endpoints.
        
        Args:
            include_optional: Whether to include optional parameters in test cases
            
        Returns:
            List of test cases
        """
        test_cases = []
        
        for request in self.requests:
            # Create a test case with default values
            test_case = TestCase(
                request=request,
                description=f"Test {request.method.upper()} {request.path}",
                tags=[request.method.lower(), request.path.strip("/").split("/")[0] or "root"]
            )
            
            # Add security requirements
            test_case.security_requirements = request.security
            
            # Set expected status codes based on operation
            responses = self.parsed_spec.get("paths", {}).get(request.path, {}).get(request.method.value, {}).get("responses", {})
            test_case.expected_status_codes = [int(code) for code in responses.keys() if code.isdigit()]
            
            test_cases.append(test_case)
        
        return test_cases
    
    async def execute_test_case(self, test_case: TestCase, 
                              session: Optional[aiohttp.ClientSession] = None) -> Dict:
        """Execute a test case against the API.
        
        Args:
            test_case: The test case to execute
            session: Optional aiohttp client session
            
        Returns:
            Dictionary with test results
        """
        close_session = False
        if session is None:
            session = aiohttp.ClientSession()
            close_session = True
        
        result = {
            "test_case": test_case.description,
            "url": test_case.request.url,
            "method": test_case.request.method.value.upper(),
            "status": "pending",
            "status_code": None,
            "response_time_ms": 0,
            "error": None,
            "request_headers": {},
            "response_headers": {},
            "request_body": None,
            "response_body": None
        }
        
        try:
            # Prepare request data
            headers = test_case.request.get_headers()
            cookies = test_case.request.get_cookies()
            body = test_case.request.get_body()
            
            # Update result with request details
            result["request_headers"] = headers
            if cookies:
                result["cookies"] = cookies
            if body:
                result["request_body"] = body
            
            # Make the request
            start_time = asyncio.get_event_loop().time()
            
            async with session.request(
                method=test_case.request.method.value,
                url=test_case.request.url,
                headers=headers,
                cookies=cookies,
                json=body if isinstance(body, dict) else None,
                data=body if isinstance(body, str) else None,
                allow_redirects=False
            ) as response:
                # Calculate response time
                end_time = asyncio.get_event_loop().time()
                response_time_ms = int((end_time - start_time) * 1000)
                
                # Get response data
                response_body = await response.text()
                
                # Update result
                result.update({
                    "status": "completed",
                    "status_code": response.status,
                    "response_time_ms": response_time_ms,
                    "response_headers": dict(response.headers),
                    "response_body": response_body,
                    "success": response.status in test_case.expected_status_codes
                })
                
        except Exception as e:
            result.update({
                "status": "error",
                "error": str(e)
            })
        
        finally:
            if close_session and not session.closed:
                await session.close()
        
        return result

# Helper function to load an OpenAPI spec
def load_openapi_spec(spec: Union[str, Dict], base_url: str = "") -> 'OpenAPIParser':
    """Helper function to load an OpenAPI specification.
    
    Args:
        spec: The OpenAPI specification (URL, file path, or dict)
        base_url: Base URL for the API (overrides servers/host if provided)
        
    Returns:
        OpenAPIParser instance
    """
    parser = OpenAPIParser(spec, base_url)
    return parser

# Example usage
async def example_usage():
    """Example usage of the OpenAPI parser."""
    # Example with a URL
    parser = OpenAPIParser("https://petstore.swagger.io/v2/swagger.json")
    await parser.load()
    
    # Generate test cases
    test_cases = parser.generate_test_cases()
    
    # Execute test cases
    async with aiohttp.ClientSession() as session:
        for test_case in test_cases[:5]:  # Just test first 5 endpoints
            result = await parser.execute_test_case(test_case, session)
            print(f"{result['method']} {result['url']} - {result['status_code']} ({result['response_time_ms']}ms)")

if __name__ == "__main__":
    asyncio.run(example_usage())

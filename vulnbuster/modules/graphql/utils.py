""
Utility functions for GraphQL operations.
"""

import re
from typing import Any, Dict, List, Optional, Set, Union


def is_graphql_endpoint(content_type: Optional[str], response_text: str) -> bool:
    """
    Check if a response is from a GraphQL endpoint.
    
    Args:
        content_type: The Content-Type header from the response
        response_text: The response body as text
        
    Returns:
        bool: True if the response appears to be from a GraphQL endpoint
    """
    # Check Content-Type header
    if content_type and 'application/json' in content_type:
        try:
            # Check for common GraphQL response patterns
            if any(
                key in response_text.lower() 
                for key in ['"data"', '"errors"', '"query"']
            ):
                return True
        except:
            pass
    
    # Check for GraphQL error messages
    graphql_indicators = [
        'query', 'mutation', 'subscription',
        'GraphQL', 'graphql',
        'query {', 'mutation {', 'subscription {',
        'query\n', 'mutation\n', 'subscription\n',
        'query\r\n', 'mutation\r\n', 'subscription\r\n'
    ]
    
    return any(indicator in response_text for indicator in graphql_indicators)


def find_graphql_endpoints(html_content: str) -> List[str]:
    """
    Find potential GraphQL endpoints in HTML content.
    
    Args:
        html_content: The HTML content to search through
        
    Returns:
        List of potential GraphQL endpoint URLs
    """
    endpoints = set()
    
    # Common GraphQL endpoint patterns
    patterns = [
        r'https?://[^\s"\']+/graphql',
        r'https?://[^\s"\']+/api/graphql',
        r'https?://[^\s"\']+/graphql/api',
        r'https?://[^\s"\']+/gql',
        r'https?://[^\s"\']+/query',
        r'https?://[^\s"\']+\/graphql(?:\.(?:php|py|js|go|rb|java))?',
        r'https?://[^\s"\']+/graphiql',
        r'https?://[^\s"\']+/playground',
        r'https?://[^\s"\']+/altair',
        r'https?://[^\s"\']+/voyager',
        r'https?://[^\s"\']+/graphql/console',
        r'https?://[^\s"\']+/graphql/explorer',
    ]
    
    # Search for patterns in the HTML
    for pattern in patterns:
        matches = re.finditer(pattern, html_content, re.IGNORECASE)
        for match in matches:
            endpoints.add(match.group(0))
    
    # Also check for common JavaScript variables that might contain GraphQL endpoints
    js_patterns = [
        r'const\s+GRAPHQL_ENDPOINT\s*=\s*["\']([^"\']+)["\']',
        r'const\s+API_URL\s*=\s*["\']([^"\']+graphql[^"\']*)["\']',
        r'endpoint\s*:\s*["\']([^"\']+graphql[^"\']*)["\']',
        r'uri\s*:\s*["\']([^"\']+graphql[^"\']*)["\']',
        r'url\s*\(\s*[\'"]([^\'")]+graphql[^\'")]*)[\'"][\s\S]*?\)',
    ]
    
    for pattern in js_patterns:
        matches = re.finditer(pattern, html_content, re.IGNORECASE)
        for match in matches:
            if len(match.groups()) > 0:
                endpoints.add(match.group(1))
    
    # Clean up the endpoints (remove any trailing slashes or query parameters)
    cleaned_endpoints = set()
    for endpoint in endpoints:
        # Remove query parameters
        endpoint = endpoint.split('?')[0]
        # Remove fragments
        endpoint = endpoint.split('#')[0]
        # Remove trailing slashes
        endpoint = endpoint.rstrip('/')
        cleaned_endpoints.add(endpoint)
    
    return list(cleaned_endpoints)


def generate_sample_queries(schema: Dict[str, Any], count: int = 5) -> List[Dict[str, Any]]:
    """
    Generate sample GraphQL queries based on a schema.
    
    Args:
        schema: The GraphQL schema
        count: Number of sample queries to generate
        
    Returns:
        List of sample queries
    """
    # This is a simplified example - in a real implementation, you would
    # analyze the schema and generate meaningful queries
    sample_queries = []
    
    # Generate a simple query for each type in the schema
    for type_name, type_def in schema.get('types', {}).items():
        if type_def.get('kind') == 'OBJECT' and type_name.startswith('Query'):
            for field in type_def.get('fields', []):
                query = f'{{ {field["name"]} {{ __typename }} }}'
                sample_queries.append({
                    'query': query,
                    'description': f'Simple query for {field["name"]}'
                })
                
                if len(sample_queries) >= count:
                    return sample_queries
    
    return sample_queries


def analyze_query_complexity(query: str) -> Dict[str, int]:
    """
    Analyze the complexity of a GraphQL query.
    
    Args:
        query: The GraphQL query string
        
    Returns:
        Dict containing complexity metrics
    """
    # Remove comments
    query = re.sub(r'#.*?\n', '', query)
    
    # Count fields
    field_count = len(re.findall(r'\w+\s*(?=\{|\()', query))
    
    # Count depth
    depth = 0
    max_depth = 0
    for char in query:
        if char == '{':
            depth += 1
            max_depth = max(max_depth, depth)
        elif char == '}':
            depth -= 1
    
    # Count aliases
    alias_count = len(re.findall(r'\w+\s*:', query))
    
    # Count fragments
    fragment_count = len(re.findall(r'fragment\s+\w+', query, re.IGNORECASE))
    
    return {
        'field_count': field_count,
        'max_depth': max_depth,
        'alias_count': alias_count,
        'fragment_count': fragment_count,
        'query_length': len(query)
    }

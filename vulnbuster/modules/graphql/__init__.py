""
GraphQL Deep Fuzzer Module

This module provides advanced fuzzing capabilities for GraphQL APIs,
including query introspection, type-based parameter mutation, and
AI-powered chain suggestion.
"""

from typing import Dict, List, Optional, Any, Union
import json
import random
import string
from dataclasses import dataclass, field
from enum import Enum

import aiohttp

class GraphQLOperationType(str, Enum):
    """Type of GraphQL operation."""
    QUERY = "query"
    MUTATION = "mutation"
    SUBSCRIPTION = "subscription"

@dataclass
class GraphQLType:
    """Represents a GraphQL type."""
    name: str
    kind: str
    description: str = ""
    fields: List[Dict] = field(default_factory=list)
    input_fields: List[Dict] = field(default_factory=list)
    enum_values: List[Dict] = field(default_factory=list)
    of_type: Optional[Dict] = None

@dataclass
class GraphQLField:
    """Represents a GraphQL field."""
    name: str
    type: Dict
    args: List[Dict] = field(default_factory=list)
    description: str = ""
    is_deprecated: bool = False
    deprecation_reason: Optional[str] = None

class GraphQLFuzzer:
    """Advanced GraphQL fuzzer with introspection and AI capabilities."""
    
    def __init__(self, endpoint: str, session: Optional[aiohttp.ClientSession] = None):
        """Initialize the GraphQL fuzzer.
        
        Args:
            endpoint: The GraphQL endpoint URL
            session: Optional aiohttp client session
        """
        self.endpoint = endpoint
        self.session = session or aiohttp.ClientSession()
        self.schema: Dict[str, Any] = {}
        self.types: Dict[str, GraphQLType] = {}
        self.queries: List[GraphQLField] = []
        self.mutations: List[GraphQLField] = []
        self.subscriptions: List[GraphQLField] = []
    
    async def introspect(self) -> bool:
        """Perform GraphQL introspection to get the schema.
        
        Returns:
            bool: True if introspection was successful, False otherwise
        """
        introspection_query = """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              ...FullType
            }
            directives {
              name
              description
              locations
              args {
                ...InputValue
              }
            }
          }
        }
        
        fragment FullType on __Type {
          kind
          name
          description
          fields(includeDeprecated: true) {
            name
            description
            args {
              ...InputValue
            }
            type {
              ...TypeRef
            }
            isDeprecated
            deprecationReason
          }
          inputFields {
            ...InputValue
          }
          interfaces {
            ...TypeRef
          }
          enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
          }
          possibleTypes {
            ...TypeRef
          }
        }
        
        fragment InputValue on __InputValue {
          name
          description
          type { ...TypeRef }
          defaultValue
        }
        
        fragment TypeRef on __Type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
        """
        
        try:
            async with self.session.post(
                self.endpoint,
                json={"query": introspection_query},
                headers={"Content-Type": "application/json"}
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    self.schema = result.get("data", {}).get("__schema", {})
                    self._process_schema()
                    return True
        except Exception as e:
            print(f"Error during introspection: {e}")
        
        return False
    
    def _process_schema(self) -> None:
        """Process the introspected schema and populate type information."""
        if not self.schema:
            return
        
        # Process all types
        for type_info in self.schema.get("types", []):
            type_name = type_info.get("name")
            if not type_name or type_name.startswith("__"):
                continue
                
            self.types[type_name] = GraphQLType(
                name=type_name,
                kind=type_info.get("kind", ""),
                description=type_info.get("description", ""),
                fields=type_info.get("fields", []),
                input_fields=type_info.get("inputFields", []),
                enum_values=type_info.get("enumValues", []),
                of_type=type_info.get("ofType")
            )
        
        # Process queries, mutations, and subscriptions
        query_type = self.schema.get("queryType", {}).get("name")
        mutation_type = self.schema.get("mutationType", {}).get("name")
        subscription_type = self.schema.get("subscriptionType", {}).get("name")
        
        if query_type and query_type in self.types:
            self.queries = self.types[query_type].fields
        if mutation_type and mutation_type in self.types:
            self.mutations = self.types[mutation_type].fields
        if subscription_type and subscription_type in self.types:
            self.subscriptions = self.types[subscription_type].fields
    
    async def generate_test_queries(self, operation_type: GraphQLOperationType = GraphQLOperationType.QUERY) -> List[str]:
        """Generate test queries based on the schema.
        
        Args:
            operation_type: Type of operation to generate queries for
            
        Returns:
            List of generated GraphQL queries
        """
        operations = []
        if operation_type == GraphQLOperationType.QUERY:
            operations = self.queries
        elif operation_type == GraphQLOperationType.MUTATION:
            operations = self.mutations
        elif operation_type == GraphQLOperationType.SUBSCRIPTION:
            operations = self.subscriptions
        
        queries = []
        for op in operations:
            query = self._generate_operation(operation_type.value, op)
            if query:
                queries.append(query)
        
        return queries
    
    def _generate_operation(self, operation_type: str, field: Dict) -> Optional[str]:
        """Generate a GraphQL operation for a field.
        
        Args:
            operation_type: Type of operation (query, mutation, subscription)
            field: Field information from introspection
            
        Returns:
            Generated GraphQL operation as a string, or None if invalid
        """
        if not field or not field.get("name"):
            return None
        
        field_name = field["name"]
        args = self._generate_args(field.get("args", []))
        selection_set = self._generate_selection_set(field.get("type", {}))
        
        if not selection_set:
            selection_set = ""
            
        return f"{operation_type} {{ {field_name}{args}{selection_set} }}"
    
    def _generate_args(self, args: List[Dict]) -> str:
        """Generate arguments for a field."""
        if not args:
            return ""
            
        arg_strings = []
        for arg in args:
            arg_name = arg.get("name")
            if not arg_name:
                continue
                
            arg_type = arg.get("type", {})
            arg_value = self._generate_arg_value(arg_type)
            if arg_value is not None:
                arg_strings.append(f"{arg_name}: {json.dumps(arg_value)}")
        
        if not arg_strings:
            return ""
            
        return f"({', '.join(arg_strings)})"
    
    def _generate_arg_value(self, arg_type: Dict) -> Any:
        """Generate a value for an argument based on its type."""
        if not arg_type:
            return None
            
        kind = arg_type.get("kind")
        name = arg_type.get("name")
        of_type = arg_type.get("ofType")
        
        # Handle non-null types
        if kind == "NON_NULL":
            if of_type:
                return self._generate_arg_value(of_type)
            return None
        
        # Handle list types
        if kind == "LIST":
            if of_type:
                return [self._generate_arg_value(of_type)]
            return []
        
        # Handle scalar types
        if kind == "SCALAR":
            if name == "String":
                return "".join(random.choices(string.ascii_letters + string.digits, k=10))
            elif name == "Int":
                return random.randint(1, 100)
            elif name == "Float":
                return random.uniform(1.0, 100.0)
            elif name == "Boolean":
                return random.choice([True, False])
            elif name == "ID":
                return "id_" + "".join(random.choices(string.ascii_letters + string.digits, k=8))
            else:
                return "".join(random.choices(string.ascii_letters + string.digits, k=10))
        
        # Handle enum types
        if kind == "ENUM":
            if name and name in self.types:
                enum_values = self.types[name].enum_values
                if enum_values:
                    return random.choice(enum_values)["name"]
            return "ENUM_VALUE"
        
        # Handle input object types
        if kind == "INPUT_OBJECT":
            if name and name in self.types:
                input_fields = self.types[name].input_fields
                if input_fields:
                    obj = {}
                    for field in input_fields:
                        field_name = field.get("name")
                        if field_name:
                            field_type = field.get("type", {})
                            obj[field_name] = self._generate_arg_value(field_type)
                    return obj
            return {}
        
        return None
    
    def _generate_selection_set(self, type_info: Dict, depth: int = 0, max_depth: int = 2) -> str:
        """Generate a selection set for a type."""
        if depth >= max_depth or not type_info:
            return ""
            
        kind = type_info.get("kind")
        name = type_info.get("name")
        of_type = type_info.get("ofType")
        
        # Handle non-null and list types
        if kind in ["NON_NULL", "LIST"] and of_type:
            return self._generate_selection_set(of_type, depth, max_depth)
        
        # Handle object types
        if kind == "OBJECT" and name and name in self.types:
            fields = self.types[name].fields
            if not fields:
                return ""
                
            # Select a subset of fields (up to 3) to avoid too large queries
            selected_fields = random.sample(fields, min(3, len(fields))) if len(fields) > 3 else fields
            
            field_selections = []
            for field in selected_fields:
                field_name = field.get("name")
                if not field_name:
                    continue
                    
                field_type = field.get("type", {})
                sub_selection = self._generate_selection_set(field_type, depth + 1, max_depth)
                
                if sub_selection:
                    field_selections.append(f"{field_name} {sub_selection}")
                else:
                    field_selections.append(field_name)
            
            if not field_selections:
                return ""
                
            return f"{{ {' '.join(field_selections)} }}"
        
        return ""
    
    async def fuzz_endpoint(self, query: str, variables: Optional[Dict] = None) -> Dict:
        """Send a GraphQL query to the endpoint.
        
        Args:
            query: The GraphQL query
            variables: Optional variables for the query
            
        Returns:
            Response from the server
        """
        if not self.session:
            return {"error": "No active session"}
            
        payload = {"query": query}
        if variables:
            payload["variables"] = variables
            
        try:
            async with self.session.post(
                self.endpoint,
                json=payload,
                headers={"Content-Type": "application/json"}
            ) as response:
                return await response.json()
        except Exception as e:
            return {"error": str(e)}
    
    async def close(self) -> None:
        """Close the HTTP session."""
        if self.session and not self.session.closed:
            await self.session.close()

    async def __aenter__(self):
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()

"""
GraphQL Client with schema introspection and query generation capabilities.
"""

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Union

import aiohttp
from graphql import build_client_schema, get_introspection_query
from graphql.language import parse
from pydantic import BaseModel, HttpUrl

from vulnbuster.interfaces.http_client import HTTPClient
from vulnbuster.interfaces.enhanced_scanner import EnhancedActiveScanner


class GraphQLType(BaseModel):
    """Represents a GraphQL type definition."""
    name: str
    kind: str
    description: Optional[str] = None
    fields: List[Dict[str, Any]] = []
    input_fields: List[Dict[str, Any]] = []
    interfaces: List[Dict[str, str]] = []
    enum_values: List[Dict[str, str]] = []
    possible_types: List[Dict[str, str]] = []


class GraphQLSchema(BaseModel):
    """Represents a complete GraphQL schema."""
    query_type: GraphQLType
    mutation_type: Optional[GraphQLType] = None
    subscription_type: Optional[GraphQLType] = None
    types: Dict[str, GraphQLType] = {}
    directives: List[Dict[str, Any]] = []


@dataclass
class GraphQLQuery:
    """Represents a GraphQL query with its variables."""
    query: str
    variables: Dict[str, Any] = field(default_factory=dict)
    operation_name: Optional[str] = None


class GraphQLClient:
    """Asynchronous GraphQL client with schema introspection and query generation."""
    
    def __init__(
        self,
        endpoint: str,
        headers: Optional[Dict[str, str]] = None,
        http_client: Optional[HTTPClient] = None,
        timeout: int = 30
    ):
        """
        Initialize the GraphQL client.
        
        Args:
            endpoint: GraphQL endpoint URL
            headers: Optional HTTP headers
            http_client: Optional HTTP client instance
            timeout: Request timeout in seconds
        """
        self.endpoint = endpoint
        self.headers = headers or {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        self.timeout = timeout
        self.schema: Optional[GraphQLSchema] = None
        self._http_client = http_client or HTTPClient()
        self._type_cache: Dict[str, GraphQLType] = {}
    
    async def introspect_schema(self) -> GraphQLSchema:
        """
        Introspect the GraphQL schema and build a schema object.
        
        Returns:
            GraphQLSchema: The introspected schema
            
        Raises:
            Exception: If schema introspection fails
        """
        introspection_query = get_introspection_query(descriptions=True)
        
        try:
            response = await self._http_client.post(
                self.endpoint,
                headers=self.headers,
                json={"query": introspection_query}
            )
            
            if response.status_code != 200:
                raise Exception(f"Schema introspection failed with status {response.status_code}")
                
            schema_data = response.json()
            
            if "errors" in schema_data:
                raise Exception(f"Schema introspection errors: {schema_data['errors']}")
            
            # Build the schema using graphql-core
            client_schema = build_client_schema(schema_data["data"])
            
            # Convert to our schema model
            self.schema = self._build_schema_model(schema_data["data"]["__schema"])
            return self.schema
            
        except Exception as e:
            raise Exception(f"Failed to introspect schema: {str(e)}")
    
    def _build_schema_model(self, schema_data: Dict[str, Any]) -> GraphQLSchema:
        ""Build a GraphQLSchema model from introspection data."""
        # Build type cache first
        self._type_cache = {}
        for type_data in schema_data["types"]:
            self._type_cache[type_data["name"]] = GraphQLType(**type_data)
        
        # Build schema with references to types
        return GraphQLSchema(
            query_type=self._type_cache[schema_data["queryType"]["name"]],
            mutation_type=self._type_cache[schema_data["mutationType"]["name"]] if schema_data.get("mutationType") else None,
            subscription_type=self._type_cache[schema_data["subscriptionType"]["name"]] if schema_data.get("subscriptionType") else None,
            types=self._type_cache,
            directives=schema_data.get("directives", [])
        )
    
    async def execute_query(
        self,
        query: str,
        variables: Optional[Dict[str, Any]] = None,
        operation_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Execute a GraphQL query.
        
        Args:
            query: The GraphQL query string
            variables: Optional query variables
            operation_name: Optional operation name
            
        Returns:
            Dict containing the response data
            
        Raises:
            Exception: If the query execution fails
        """
        payload = {"query": query}
        
        if variables:
            payload["variables"] = variables
        if operation_name:
            payload["operationName"] = operation_name
            
        try:
            response = await self._http_client.post(
                self.endpoint,
                headers=self.headers,
                json=payload,
                timeout=self.timeout
            )
            
            if response.status_code != 200:
                raise Exception(f"Query failed with status {response.status_code}")
                
            result = response.json()
            
            if "errors" in result:
                raise Exception(f"GraphQL errors: {result['errors']}")
                
            return result.get("data", {})
            
        except Exception as e:
            raise Exception(f"Failed to execute query: {str(e)}")
    
    def generate_queries(self, depth: int = 2) -> List[GraphQLQuery]:
        """
        Generate sample queries based on the schema.
        
        Args:
            depth: Maximum depth of nested fields to include
            
        Returns:
            List of generated GraphQL queries
        """
        if not self.schema:
            raise Exception("Schema not introspected. Call introspect_schema() first.")
            
        queries = []
        
        # Generate queries for query type
        if self.schema.query_type:
            for field in self.schema.query_type.fields:
                query = self._generate_field_query(
                    field["name"],
                    field["type"],
                    depth=depth
                )
                if query:
                    queries.append(GraphQLQuery(query=query))
        
        return queries
    
    def _generate_field_query(
        self,
        field_name: str,
        field_type: Dict[str, Any],
        depth: int,
        parent_types: Optional[Set[str]] = None
    ) -> Optional[str]:
        """Recursively generate a query for a field."""
        if parent_types is None:
            parent_types = set()
            
        # Handle non-null and list types
        type_kind = field_type.get("kind", "")
        type_name = field_type.get("name", "")
        of_type = field_type.get("ofType")
        
        if type_kind in ["NON_NULL", "LIST"] and of_type:
            return self._generate_field_query(field_name, of_type, depth, parent_types)
        
        # Prevent infinite recursion on circular types
        if type_name in parent_types:
            return None
            
        # Get the type definition
        type_def = self._type_cache.get(type_name)
        if not type_def:
            return None
            
        # Handle different types of fields
        if type_def.kind == "SCALAR":
            return field_name
            
        elif type_def.kind == "OBJECT":
            if depth <= 0:
                return field_name
                
            subfields = []
            new_parents = parent_types | {type_name}
            
            for subfield in type_def.fields:
                subfield_query = self._generate_field_query(
                    subfield["name"],
                    subfield["type"],
                    depth - 1,
                    new_parents
                )
                if subfield_query:
                    subfields.append(subfield_query)
            
            if not subfields:
                return field_name
                
            return f"{field_name} {{ {' '.join(subfields)} }}"
            
        return None
    
    async def close(self):
        ""Close the HTTP client."""
        await self._http_client.close()
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

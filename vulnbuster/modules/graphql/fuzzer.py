"""
GraphQL fuzzing module for security testing.
"""

import asyncio
import random
import string
import logging
from dataclasses import dataclass, field
"""
GraphQL Fuzzer with AI-Powered Security Testing

This module provides a comprehensive fuzzing solution for GraphQL APIs, combining
traditional fuzzing techniques with AI-powered test case generation to identify
security vulnerabilities.
"""

import asyncio
import json
import logging
import random
import string
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from .ai_suggestor import AISuggestor
from .client import GraphQLClient
from .mutators import TypeMutator

from graphql.language.ast import (
    DocumentNode, OperationDefinition, Field, Name, SelectionSet,
    Argument, StringValue, IntValue, FloatValue, BooleanValue, ListValue, ObjectValue, Value
)
from graphql.language.parser import parse
from graphql.language.printer import print_ast
from graphql.language.visitor import Visitor, visit

from .client import GraphQLClient, GraphQLQuery, GraphQLSchema, GraphQLType
from .mutators import TypeMutator
from .ai_suggestor import AISuggestor
from vulnbuster.interfaces.enhanced_scanner import EnhancedActiveScanner, ScanResult
from vulnbuster.ai.prompt_oracle import PromptOracle


@dataclass
class FuzzResult:
    """Represents the result of a fuzzing operation."""
    successful: bool
    query: str
    response: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    payload: Optional[Dict[str, Any]] = None
    execution_time: Optional[float] = None


class GraphQLFuzzer:
    """
    Advanced GraphQL fuzzer with AI-powered test case generation.
    
    Features:
    - Automatic schema introspection
    - Type-based parameter mutation
    - AI-powered test case generation
    - Customizable fuzzing parameters
    - Comprehensive vulnerability reporting
    
    Example:
        client = GraphQLClient("http://example.com/graphql")
        fuzzer = GraphQLFuzzer(
            client=client,
            enable_ai_suggestions=True,
            max_ai_suggestions=10
        )
        vulnerabilities = await fuzzer.fuzz()
    """
    
    def __init__(
        self,
        client: GraphQLClient,
        max_queries: int = 100,
        timeout: int = 30,
        mutation_rate: float = 0.3,
        enable_ai_suggestions: bool = True,
        ai_temperature: float = 0.7,
        max_ai_suggestions: int = 5
    ):
        """
        Initialize the GraphQL fuzzer.
        
        Args:
            client: Initialized GraphQLClient instance
            max_depth: Maximum depth of nested fields to include in queries
            max_queries: Maximum number of queries to generate per operation
            timeout: Maximum time in seconds to spend fuzzing
            mutation_rate: Probability of mutating each argument (0.0 to 1.0)
            enable_ai_suggestions: Whether to use AI for generating test cases
            ai_temperature: Temperature for AI generation (0.0 to 1.0)
            max_ai_suggestions: Maximum number of AI suggestions to generate
        """
        self.client = client
        self.max_depth = max_depth
        self.mutation_rate = mutation_rate
        self.type_mutator = TypeMutator()
        self.logger = logging.getLogger(__name__)
        self.max_queries = max_queries
        self.timeout = timeout
        self._tested_queries: Set[str] = set()
        self._vulnerabilities: List[Dict[str, Any]] = []
        
        # Initialize AI components if enabled
        self.enable_ai_suggestions = enable_ai_suggestions
        self.ai_temperature = ai_temperature
        self.max_ai_suggestions = max_ai_suggestions
        self.ai_suggestor = None
        
        if enable_ai_suggestions:
            try:
                prompt_oracle = PromptOracle()
                self.ai_suggestor = AISuggestor(
                    prompt_oracle=prompt_oracle,
                    max_suggestions=max_ai_suggestions
                )
            except Exception as e:
                self.logger.warning(f"Failed to initialize AI suggestor: {e}")
                self.enable_ai_suggestions = False
    
    async def fuzz(self) -> List[Dict[str, Any]]:
        """
        Run all fuzzing tests against the target GraphQL endpoint.
        
        Returns:
            List of discovered vulnerabilities
        """
        self._vulnerabilities = []
        
        # Update type mutator with schema if available
        if self.client.schema:
            schema_dict = {"__schema": self.client.schema}
            self.type_mutator = TypeMutator(schema=schema_dict)
            
            # Initialize AI suggestor with schema if enabled
            if self.enable_ai_suggestions and self.ai_suggestor:
                try:
                    await self._generate_ai_suggestions(schema_dict)
                except Exception as e:
                    self.logger.error(f"Error generating AI suggestions: {e}")
        
        # Run all fuzzing tests
        await self._test_introspection()
        await self._test_field_suggestions()
        await self._test_query_depth()
        await self._test_directive_overloading()
        await self._test_batch_queries()
        await self._test_type_based_mutation()
        
        return self._vulnerabilities
    
    async def _test_introspection(self) -> None:
        """Test if introspection is enabled and extract schema information."""
        try:
            # Try to get the schema using standard introspection
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
            }"""
            
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
                type { 
                    name 
                    kind 
                    ofType { 
                        name 
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
            
            result = await self.client.execute_query(introspection_query)
            if result and "__schema" in result:
                self._add_vulnerability(
                    "Information Disclosure",
                    "GraphQL introspection is enabled",
                    "Introspection allows anyone to query the complete schema, potentially exposing sensitive information.",
                    "Consider disabling introspection in production environments.",
                    {"query": introspection_query}
                )
                
        except Exception as e:
            # Introspection is disabled or blocked
            pass
    
    async def _test_batching(self) -> None:
        ""Test for query batching vulnerabilities."""
        if not self.client.schema or not self.client.schema.query_type:
            return
            
        # Get the first query field to test with
        query_fields = [f for f in self.client.schema.query_type.fields 
                       if not f.get("isDeprecated")]
        
        if not query_fields:
            return
            
        test_field = query_fields[0]
        test_query = f"""
        query TestBatching {{
            {test_field['name']} {{
                __typename
            }}
        }}
        """
        
        # Create a batch of the same query
        batch = [{"query": test_query}] * 10
        
        try:
            response = await self.client._http_client.post(
                self.client.endpoint,
                headers=self.client.headers,
                json=batch
            )
            
            if response.status_code == 200:
                results = response.json()
                if isinstance(results, list) and len(results) == len(batch):
                    self._add_vulnerability(
                        "Denial of Service",
                        "GraphQL query batching is enabled",
                        "Batching multiple queries in a single request can lead to denial of service "
                        "attacks by overloading the server with expensive operations.",
                        "Implement rate limiting and query complexity analysis to prevent abuse.",
                        {"batch_size": len(batch), "query": test_query}
                    )
                    
        except Exception:
            # Batching not supported or an error occurred
            pass
    
    async def _test_field_suggestions(self) -> None:
        ""Test for field suggestion vulnerabilities."""
        if not self.client.schema or not self.client.schema.query_type:
            return
            
        # Generate queries with common field name typos
        common_typos = {
            "users": ["user", "usr", "usrs", "usres", "usar"],
            "email": ["emial", "emal", "emali", "emil"],
            "password": ["passwd", "pwd", "pass", "passwrd"],
            "admin": ["adm", "admn", "adim", "amin"]
        }
        
        for field in self.client.schema.query_type.fields:
            field_name = field["name"]
            
            # Skip fields that are already in our typo list
            if field_name in common_typos:
                continue
                
            # Check for fields that might be sensitive
            is_sensitive = any(
                term in field_name.lower() 
                for term in ["pass", "secret", "token", "key", "auth", "cred"]
            )
            
            if not is_sensitive:
                continue
                
            # Test with common typos
            for typo in common_typos.get(field_name, []):
                query = f"""
                query TestTypo {{
                    {typo} {{
                        __typename
                    }}
                }}
                """
                
                try:
                    result = await self.client.execute_query(query)
                    
                    # If we get a valid response, it might be suggesting the correct field
                    if result and "errors" not in result:
                        self._add_vulnerability(
                            "Information Disclosure",
                            f"Field suggestion vulnerability for '{typo}'",
                            f"The server suggests the field '{field_name}' when '{typo}' is used, "
                            "which could help an attacker discover sensitive fields.",
                            f"Disable field suggestions or implement proper error handling for unknown fields.",
                            {"query": query, "suggested_field": field_name}
                        )
                        break
                        
                except Exception:
                    # Error occurred, skip this test case
                    continue
    
    async def _test_directives(self) -> None:
        ""Test for directive-related vulnerabilities."""
        if not self.client.schema:
            return
            
        # Test for @include and @skip directives bypass
        if not self.client.schema.query_type or not self.client.schema.query_type.fields:
            return
            
        test_field = self.client.schema.query_type.fields[0]
        
        # Try to bypass @include directive with invalid values
        query = f"""
        query TestDirective($condition: Boolean!) {{
            {test_field['name']} @include(if: $condition) {{
                __typename
            }}
        }}
        """
        
        # Test with various values that might bypass the condition
        for value in ["true", "false", "null", "1", "0", "'true'", "'false'"]:
            try:
                result = await self.client.execute_query(
                    query,
                    variables={"condition": value}
                )
                
                # If we get a response without errors, the directive might be bypassable
                if result and "errors" not in result:
                    self._add_vulnerability(
                        "Security Misconfiguration",
                        f"Directive bypass with value: {value}",
                        f"The @include directive can be bypassed with value: {value}",
                        "Ensure proper type checking and validation for directive arguments.",
                        {"query": query, "variable_value": value}
                    )
                    break
                    
            except Exception:
                # Error occurred, skip this test case
                continue
    
    async def _test_query_depth_attack(self) -> None:
        ""Test for query depth attacks."""
        if not self.client.schema or not self.client.schema.query_type:
            return
            
        # Find a recursive type (a type that references itself)
        recursive_type = self._find_recursive_type()
        if not recursive_type:
            return
            
        # Generate a deep query
        deep_query = self._generate_deep_query(recursive_type, depth=20)
        
        try:
            start_time = asyncio.get_event_loop().time()
            result = await self.client.execute_query(deep_query)
            execution_time = asyncio.get_event_loop().time() - start_time
            
            # If the query was successful and took a long time, it might be vulnerable
            if result and execution_time > 5.0:  # 5 seconds threshold
                self._add_vulnerability(
                    "Denial of Service",
                    "Possible query depth attack vulnerability",
                    f"The server processed a deeply nested query ({20} levels) in {execution_time:.2f} seconds "
                    "without proper depth limiting.",
                    "Implement query depth limiting to prevent denial of service attacks.",
                    {"query_depth": 20, "execution_time": f"{execution_time:.2f}s"}
                )
                
        except Exception as e:
            # Depth limiting is working as expected
            pass
    
    def _find_recursive_type(self) -> Optional[Dict[str, Any]]:
        ""Find a recursive type in the schema."""
        if not self.client.schema:
            return None
            
        for type_name, type_def in self.client.schema.types.items():
            if type_def.kind == "OBJECT" and type_def.fields:
                # Check if any field returns the same type
                for field in type_def.fields:
                    field_type = self._resolve_type(field["type"])
                    if field_type and field_type.get("name") == type_name:
                        return {"type": type_def, "field": field}
                        
        return None
    
    def _resolve_type(self, type_ref: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        ""Resolve a type reference to its definition."""
        if not self.client.schema:
            return None
            
        if type_ref.get("kind") in ["NON_NULL", "LIST"]:
            return self._resolve_type(type_ref.get("ofType", {}))
            
        type_name = type_ref.get("name")
        if not type_name:
            return None
            
        return self.client.schema.types.get(type_name)
    
    def _generate_deep_query(
        self, 
        recursive_type: Dict[str, Any],
        depth: int,
        current_depth: int = 1
    ) -> str:
        ""Generate a deeply nested query."""
        type_def = recursive_type["type"]
        field_name = recursive_type["field"]["name"]
        
        if current_depth >= depth:
            return f"{field_name} {{ __typename }}"
            
        nested = self._generate_deep_query(recursive_type, depth, current_depth + 1)
        return f"{field_name} {{ {nested} }}"
    
    async def _test_type_based_mutation(self) -> None:
        ""Test for type-based parameter mutation vulnerabilities."""
        if not self.client.schema or not self.client.schema.query_type:
            return
            
        # Get the first query field to test with
        query_fields = [f for f in self.client.schema.query_type.fields 
                       if not f.get("isDeprecated")]
        
        if not query_fields:
            return
            
        test_field = query_fields[0]
        test_query = f"""
        query TestMutation {{
            {test_field['name']} {{
                __typename
            }}
        }}
        """
        
        # Mutate the query using type-based parameter mutation
        mutated_query = self.type_mutator.mutate_query(test_query)
        
        try:
            result = await self.client.execute_query(mutated_query)
            
            # If we get a valid response, it might be vulnerable
            if result and "errors" not in result:
                self._add_vulnerability(
                    "Type Confusion",
                    "Type-based parameter mutation vulnerability",
                    "The server processed a mutated query without proper type checking.",
                    "Implement proper type checking and validation for query parameters.",
                    {"query": test_query, "mutated_query": mutated_query}
                )
                
        except Exception:
            # Error occurred, skip this test case
            pass
    
    def _add_vulnerability(
        self,
        category: str,
        title: str,
        description: str,
        remediation: str,
        evidence: Dict[str, Any],
        severity: Optional[str] = None,
        source: str = "fuzzer"
    ) -> None:
        """
        Add a vulnerability to the results.
        
        Args:
            category: Vulnerability category (e.g., "Information Disclosure")
            title: Short title of the vulnerability
            description: Detailed description
            remediation: Recommended remediation steps
            evidence: Supporting evidence for the finding
            severity: Optional severity level (overrides auto-detection)
            source: Source of the finding (e.g., 'fuzzer', 'ai')
        """
        if severity is None:
            severity = self._determine_severity(category)
            
        self._vulnerabilities.append({
            "category": category,
            "title": title,
            "description": description,
            "remediation": remediation,
            "evidence": evidence,
            "severity": severity,
            "source": source
        })
    
    def _determine_severity(self, category: str) -> str:
        """Determine the severity of a vulnerability based on its category."""
        severity_map = {
            # Critical vulnerabilities
            "Remote Code Execution": "critical",
            "SQL Injection": "critical",
            "NoSQL Injection": "critical",
            "Command Injection": "critical",
            "Server-Side Request Forgery": "critical",
            "Authentication Bypass": "critical",
            "Privilege Escalation": "critical",
            
            # High severity
            "Denial of Service": "high",
            "Injection": "high",
            "Broken Authentication": "high",
            "Type Confusion": "high",
            "Path Traversal": "high",
            "File Inclusion": "high",
            "XXE Injection": "high",
            "Insecure Deserialization": "high",
            "Business Logic Flaw": "high",
            
            # Medium severity
            "Information Disclosure": "medium",
            "Security Misconfiguration": "medium",
            "Input Validation": "medium",
            "Cross-Site Scripting (XSS)": "medium",
            "Cross-Site Request Forgery (CSRF)": "medium",
            "Insecure Direct Object Reference": "medium",
            "Broken Access Control": "medium",
            "Sensitive Data Exposure": "medium",
            
            # Low severity
            "Security Headers Missing": "low",
            "Information Leakage": "low",
            "Clickjacking": "low",
            "CORS Misconfiguration": "low"
        }
        return severity_map.get(category, "medium")
        
    async def _generate_ai_suggestions(self, schema: Dict[str, Any]) -> None:
        """
        Generate AI-powered test cases and add them to the test queue.
        
        Args:
            schema: The GraphQL schema
        """
        if not self.enable_ai_suggestions or not self.ai_suggestor:
            return
            
        self.logger.info("Generating AI-powered test cases...")
        
        try:
            # Get the query and mutation types from the schema
            query_type = schema["__schema"].get("queryType", {}).get("name")
            mutation_type = schema["__schema"].get("mutationType", {}).get("name")
            
            # Generate query chains
            query_chains = await self.ai_suggestor.suggest_query_chains(
                schema=schema,
                target_types=[query_type] if query_type else None,
                max_depth=self.max_depth,
                max_width=3
            )
            
            # Process query chain suggestions
            for suggestion in query_chains[:self.max_ai_suggestions]:
                self._add_ai_suggestion(suggestion, "query_chain")
            
            # Generate mutation chains if mutations exist
            if mutation_type:
                mutation_chains = await self.ai_suggestor.suggest_mutation_chains(
                    schema=schema,
                    target_types=[mutation_type],
                    max_steps=3
                )
                
                # Process mutation chain suggestions
                for suggestion in mutation_chains[:self.max_ai_suggestions]:
                    self._add_ai_suggestion(suggestion, "mutation_chain")
            
            # Get interesting fields for testing
            for type_name in [query_type, mutation_type]:
                if not type_name:
                    continue
                    
                interesting_fields = await self.ai_suggestor.get_interesting_fields(
                    type_name=type_name,
                    schema=schema
                )
                
                # Process field suggestions
                for field in interesting_fields[:self.max_ai_suggestions]:
                    self._add_ai_suggestion(field, "field_test")
            
            self.logger.info(f"Generated {len(query_chains)} AI-powered test cases")
            
        except Exception as e:
            self.logger.error(f"Error in AI suggestion generation: {e}")
    
    def _add_ai_suggestion(self, suggestion: Dict[str, Any], suggestion_type: str) -> None:
        """
        Add an AI-generated suggestion to the test queue.
        
        Args:
            suggestion: The AI-generated suggestion
            suggestion_type: Type of suggestion (query_chain, mutation_chain, field_test)
        """
        if not suggestion:
            return
            
        # Create a unique ID for this test case
        test_id = f"ai_{suggestion_type}_{hash(frozenset(suggestion.items()))}"
        
        # Skip if we've already tested this case
        if test_id in self._tested_queries:
            return
            
        # Add to tested queries
        self._tested_queries.add(test_id)
        
        # Create a test case based on the suggestion type
        if suggestion_type == "query_chain":
            self._add_ai_query_chain_test(suggestion)
        elif suggestion_type == "mutation_chain":
            self._add_ai_mutation_chain_test(suggestion)
        elif suggestion_type == "field_test":
            self._add_ai_field_test(suggestion)
    
    def _add_ai_query_chain_test(self, suggestion: Dict[str, Any]) -> None:
        """Add an AI-generated query chain test."""
        query = suggestion.get("query")
        if not query:
            return
            
        # Create a test case
        test_case = {
            "name": f"AI-Generated Query: {suggestion.get('name', 'Unnamed')}",
            "description": suggestion.get("description", "AI-generated query chain"),
            "query": query,
            "impact": suggestion.get("impact", "medium"),
            "category": "AI-Generated Test Case"
        }
        
        # Add to test queue if it exists
        if hasattr(self, '_test_queue'):
            self._test_queue.append(test_case)
        else:
            self._tested_queries.add(test_case["query"])
    
    def _add_ai_mutation_chain_test(self, suggestion: Dict[str, Any]) -> None:
        """Add an AI-generated mutation chain test."""
        mutations = suggestion.get("mutations", [])
        if not mutations:
            return
            
        # Create a test case for each mutation in the chain
        for i, mutation in enumerate(mutations, 1):
            test_case = {
                "name": f"AI-Generated Mutation {i}: {suggestion.get('name', 'Unnamed')}",
                "description": f"Step {i} of AI-generated mutation chain: {suggestion.get('description', '')}",
                "query": mutation,
                "impact": suggestion.get("impact", "high"),
                "category": "AI-Generated Test Case"
            }
            
            # Add to test queue if it exists
            if hasattr(self, '_test_queue'):
                self._test_queue.append(test_case)
            else:
                self._tested_queries.add(test_case["query"])
    
    def _add_ai_field_test(self, suggestion: Dict[str, Any]) -> None:
        """Add an AI-generated field test."""
        field_name = suggestion.get("name")
        if not field_name:
            return
            
        # Create test cases for each suggested value
        test_values = suggestion.get("test_values", [])
        for value in test_values:
            query = f"query {{ {field_name}(input: {json.dumps(value)}) {{ id }} }}"
            test_case = {
                "name": f"AI Field Test: {field_name} = {value}",
                "description": f"AI-suggested test for field '{field_name}': {suggestion.get('reason', '')}",
                "query": query,
                "impact": suggestion.get("impact", "medium"),
                "category": "AI-Generated Test Case"
            }
            
            # Add to test queue if it exists, otherwise add to tested queries
            if hasattr(self, '_test_queue'):
                self._test_queue.append(test_case)
            else:
                self._tested_queries.add(query)

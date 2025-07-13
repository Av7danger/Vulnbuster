"""
AI-powered suggestion engine for GraphQL fuzzing.

This module provides intelligent test case generation for GraphQL APIs
using AI/ML techniques to identify potential security vulnerabilities.
"""

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from graphql import build_schema, parse
from graphql.language.ast import DocumentNode

# Configure logging
logger = logging.getLogger(__name__)

# Default prompt templates
DEFAULT_QUERY_PROMPT = """
Generate {count} security-focused GraphQL query test cases for the following schema.
Focus on:
- Access control issues
- Information disclosure
- Complex nested queries
- Performance impacts

Schema:
```
{schema}
```

Return a JSON array of test cases, each with:
- name: Short descriptive name
- query: The GraphQL query
- impact: Potential impact (low/medium/high)
- description: Brief explanation

JSON:"""

DEFAULT_MUTATION_PROMPT = """
Generate {count} security-focused GraphQL mutation test cases for the following schema.
Focus on:
- Business logic flaws
- Data validation bypasses
- Privilege escalation
- Data tampering

Schema:
```
{schema}
```

Return a JSON array of test cases, each with:
- name: Short descriptive name
- mutation: The GraphQL mutation
- input: Sample input data
- impact: Potential impact (low/medium/high)
- description: Brief explanation

JSON:"""

DEFAULT_FIELD_TEST_PROMPT = """
Generate {count} security-focused field test cases for the following GraphQL type.
Focus on:
- Injection attacks
- Type confusion
- Boundary testing
- Special character handling

Type: {type_name}
Schema:
```
{schema}
```

Return a JSON array of test cases, each with:
- name: Short descriptive name
- field: The field being tested
- value: Test value to use
- impact: Potential impact (low/medium/high)
- description: Brief explanation

JSON:""".prompt_oracle import PromptOracle

logger = logging.getLogger(__name__)

class AISuggestor:
    """AI-powered suggestion engine for GraphQL fuzzing.
    
    This class generates security-focused test cases for GraphQL APIs using
    AI/ML techniques. It can suggest query chains, mutation chains, and
    interesting field values to test.
    
    Example:
        oracle = PromptOracle(api_key="your-ai-api-key")
        suggestor = AISuggestor(oracle)
        
        # Get query suggestions
        queries = await suggestor.suggest_query_chains(schema)
        
        # Get mutation suggestions
        mutations = await suggestor.suggest_mutation_chains(schema)
        
        # Get field test cases
        field_tests = await suggestor.suggest_field_tests(schema, "User")
    """
    
    def __init__(self, prompt_oracle, max_suggestions: int = 20):
        """Initialize the AI suggestor.
        
        Args:
            prompt_oracle: Oracle for generating AI prompts. Must implement
                          an async generate() method that takes a prompt string
                          and returns a string response.
            max_suggestions: Maximum number of suggestions to generate per type
        """
        self.prompt_oracle = prompt_oracle
        self.max_suggestions = max_suggestions
        self.cache: Dict[str, List[Dict[str, Any]]] = {}
        self._schema = None
        
        # Configure logging
        self.logger = logging.getLogger(f"{__name__}.AISuggestor")

    async def suggest_query_chains(
        self, 
        schema: Dict[str, Any],
        target_types: Optional[List[str]] = None,
        max_depth: int = 3,
        max_width: int = 3
    ) -> List[Dict[str, Any]]:
        """
        Generate suggested query chains using AI.
        
        Args:
            schema: The GraphQL schema
            target_types: List of target types to focus on
            max_depth: Maximum depth of query chains
            max_width: Maximum width (branches) at each level
            
        Returns:
            List of suggested query chains with metadata
        """
        cache_key = f"query_chains_{'_'.join(target_types or [])}_{max_depth}_{max_width}"
        
        # Check cache first
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        # Prepare the prompt
        prompt = self._build_query_chain_prompt(schema, target_types, max_depth, max_width)
        
        try:
            # Get AI suggestions
            response = await self.prompt_oracle.generate(
                prompt=prompt,
                max_tokens=2000,
                temperature=0.7,
                n=self.max_suggestions,
                stop=["---"]
            )
            
            # Parse the response
            suggestions = self._parse_ai_response(response)
            
            # Cache the results
            self._cache[cache_key] = suggestions
            
            return suggestions
            
        except Exception as e:
            logger.error(f"Error generating query chain suggestions: {e}")
            return []
    
    async def suggest_mutation_chains(
        self,
        schema: Dict[str, Any],
        target_types: Optional[List[str]] = None,
        max_steps: int = 3
    ) -> List[Dict[str, Any]]:
        """
        Generate suggested mutation chains using AI.
        
        Args:
            schema: The GraphQL schema
            target_types: List of target types to focus on
            max_steps: Maximum number of mutation steps
            
        Returns:
            List of suggested mutation chains with metadata
        """
        cache_key = f"mutation_chains_{'_'.join(target_types or [])}_{max_steps}"
        
        # Check cache first
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        # Prepare the prompt
        prompt = self._build_mutation_chain_prompt(schema, target_types, max_steps)
        
        try:
            # Get AI suggestions
            response = await self.prompt_oracle.generate(
                prompt=prompt,
                max_tokens=2000,
                temperature=0.7,
                n=self.max_suggestions,
                stop=["---"]
            )
            
            # Parse the response
            suggestions = self._parse_ai_response(response)
            
            # Cache the results
            self._cache[cache_key] = suggestions
            
            return suggestions
            
        except Exception as e:
            logger.error(f"Error generating mutation chain suggestions: {e}")
            return []
    
    async def get_interesting_fields(
        self,
        schema: Dict[str, Any],
        target_types: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Get interesting fields for fuzzing using AI.
        
        Args:
            schema: The GraphQL schema
            target_types: List of target types to focus on
            
        Returns:
            List of interesting fields with test values
        """
        cache_key = f"interesting_fields_{'_'.join(target_types or [])}"
        
        # Check cache first
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        # Prepare the prompt
        prompt = self._build_interesting_fields_prompt(schema, target_types)
        
        try:
            # Get AI suggestions
            response = await self.prompt_oracle.generate(
                prompt=prompt,
                max_tokens=2000,
                temperature=0.5,  # Lower temperature for more focused suggestions
                n=min(5, self.max_suggestions),
                stop=["---"]
            )
            
            # Parse the response
            suggestions = self._parse_ai_response(response)
            
            # Cache the results
            self._cache[cache_key] = suggestions
            
            return suggestions
            
        except Exception as e:
            logger.error(f"Error generating interesting fields: {e}")
            return []
    
    def _build_query_chain_prompt(
        self,
        schema: Dict[str, Any],
        target_types: Optional[List[str]],
        max_depth: int,
        max_width: int
    ) -> str:
        """Build the prompt for query chain generation."""
        prompt = """You are a security expert specializing in GraphQL security testing. 
Your task is to generate interesting and potentially vulnerable query chains based on the provided schema.

Schema:
```
{schema_summary}
```

Guidelines:
1. Focus on queries that might expose sensitive data or cause performance issues
2. Include queries that traverse relationships between types
3. Consider edge cases like null values, empty lists, and invalid inputs
4. Target these types specifically: {target_types}
5. Maximum query depth: {max_depth}
6. Maximum width (fields per level): {max_width}

For each suggestion, provide:
- A descriptive name
- The GraphQL query
- Potential security impact (high/medium/low)
- A brief explanation of why this query is interesting

Format your response as a JSON array of objects with these fields:
- name: str
- query: str
- impact: str (high/medium/low)
- description: str

Suggestions:
"""
        # Create a summary of the schema
        schema_summary = self._summarize_schema(schema, target_types)
        
        return prompt.format(
            schema_summary=schema_summary,
            target_types=", ".join(target_types) if target_types else "all types",
            max_depth=max_depth,
            max_width=max_width
        )
    
    def _build_mutation_chain_prompt(
        self,
        schema: Dict[str, Any],
        target_types: Optional[List[str]],
        max_steps: int
    ) -> str:
        """Build the prompt for mutation chain generation."""
        prompt = """You are a security expert specializing in GraphQL security testing. 
Your task is to generate interesting and potentially dangerous mutation chains based on the provided schema.

Schema:
```
{schema_summary}
```

Guidelines:
1. Focus on mutations that might lead to unauthorized data modification or privilege escalation
2. Chain multiple mutations together to test for business logic flaws
3. Include edge cases like race conditions and invalid state transitions
4. Target these types specifically: {target_types}
5. Maximum steps in chain: {max_steps}

For each suggestion, provide:
- A descriptive name
- The GraphQL mutation chain (as an array of mutation strings)
- Potential security impact (high/medium/low)
- A brief explanation of why this mutation chain is interesting

Format your response as a JSON array of objects with these fields:
- name: str
- mutations: List[str]
- impact: str (high/medium/low)
- description: str

Suggestions:
"""
        # Create a summary of the schema
        schema_summary = self._summarize_schema(schema, target_types)
        
        return prompt.format(
            schema_summary=schema_summary,
            target_types=", ".join(target_types) if target_types else "all types",
            max_steps=max_steps
        )
    
    def _build_interesting_fields_prompt(
        self,
        schema: Dict[str, Any],
        target_types: Optional[List[str]]
    ) -> str:
        """Build the prompt for interesting fields generation."""
        prompt = """You are a security expert specializing in GraphQL security testing. 
Your task is to identify interesting fields in the provided schema that should be tested for security vulnerabilities.

Schema:
```
{schema_summary}
```

Guidelines:
1. Focus on fields that might be vulnerable to injection, information disclosure, or access control issues
2. Pay special attention to boolean flags, ID fields, and fields that might contain sensitive data
3. Target these types specifically: {target_types}

For each field, provide:
- The field name
- The reason why it's interesting for security testing
- A list of test values to try
- Potential security impact (high/medium/low)

Format your response as a JSON array of objects with these fields:
- name: str (field name)
- reason: str (why this field is interesting)
- test_values: List[Any] (values to test)
- impact: str (high/medium/low)

Suggestions:
"""
        # Create a summary of the schema
        schema_summary = self._summarize_schema(schema, target_types)
        
        return prompt.format(
            schema_summary=schema_summary,
            target_types=", ".join(target_types) if target_types else "all types"
        )
    
    def _summarize_schema(
        self,
        schema: Dict[str, Any],
        target_types: Optional[List[str]] = None
    ) -> str:
        """Create a summary of the schema for the AI prompt."""
        if not schema or "__schema" not in schema:
            return "No valid schema provided"
            
        schema_data = schema["__schema"]
        summary = []
        
        # Add query type
        if "queryType" in schema_data and schema_data["queryType"]:
            summary.append(f"Query Type: {schema_data['queryType'].get('name', 'Unknown')}")
        
        # Add mutation type if it exists
        if "mutationType" in schema_data and schema_data["mutationType"]:
            summary.append(f"Mutation Type: {schema_data['mutationType'].get('name', 'Unknown')}")
        
        # Add types
        if "types" in schema_data and schema_data["types"]:
            type_descriptions = []
            for type_info in schema_data["types"][:20]:  # Limit number of types to keep prompt size manageable
                type_name = type_info.get("name", "")
                kind = type_info.get("kind", "")
                
                # Skip built-in types and non-target types
                if type_name.startswith("__") or (target_types and type_name not in target_types):
                    continue
                
                type_desc = [f"{kind} {type_name}"]
                
                # Add fields for object types
                if kind in ["OBJECT", "INTERFACE", "INPUT_OBJECT"] and "fields" in type_info:
                    fields = type_info["fields"]
                    if fields:
                        field_descs = []
                        for field in fields[:10]:  # Limit number of fields to keep prompt size manageable
                            field_name = field.get("name", "")
                            field_type = self._get_type_name(field.get("type", {}))
                            field_args = []
                            
                            # Add field arguments
                            if "args" in field and field["args"]:
                                for arg in field["args"][:3]:  # Limit number of args
                                    arg_name = arg.get("name", "")
                                    arg_type = self._get_type_name(arg.get("type", {}))
                                    field_args.append(f"{arg_name}: {arg_type}")
                            
                            field_desc = field_name
                            if field_args:
                                field_desc += f"({', '.join(field_args)})"
                            field_desc += f": {field_type}"
                            field_descs.append(field_desc)
                        
                        type_desc.append("  " + "\n  ".join(field_descs))
                        if len(fields) > 10:
                            type_desc.append(f"  ... and {len(fields) - 10} more fields")
                
                type_descriptions.append("\n".join(type_desc))
            
            if type_descriptions:
                summary.append("\nTypes:" + "\n\n".join([""] + type_descriptions))
        
        return "\n".join(summary)
    
    def _get_type_name(self, type_info: Dict[str, Any]) -> str:
        """Get the name of a type, handling nested types."""
        if not type_info:
            return "Unknown"
            
        kind = type_info.get("kind", "")
        name = type_info.get("name", "")
        of_type = type_info.get("ofType")
        
        if kind in ["NON_NULL", "LIST"] and of_type:
            base_type = self._get_type_name(of_type)
            if kind == "NON_NULL":
                return f"{base_type}!"
            else:
                return f"[{base_type}]"
        
        return name or kind
    
    def _parse_ai_response(self, response: Union[str, List[Dict], Dict]) -> List[Dict[str, Any]]:
        """
        Parse the AI response into a structured format.
        
        Args:
            response: Raw response from the AI (string or parsed JSON)
            
        Returns:
            List of parsed suggestions
        """
        if not response:
            return []
        
        try:
            # If response is a string, try to parse it as JSON
            if isinstance(response, str):
                try:
                    response = json.loads(response)
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse AI response as JSON: {e}")
                    return []
            
            # If response is a dict, convert to list
            if isinstance(response, dict):
                response = [response]
            
            # Ensure it's a list
            if not isinstance(response, list):
                logger.error(f"Expected list in AI response, got {type(response).__name__}")
                return []
                
            # Validate each suggestion
            valid_suggestions = []
            for suggestion in response:
                if not isinstance(suggestion, dict):
                    continue
                    
                # Ensure required fields are present
                if "name" in suggestion and "query" in suggestion and "impact" in suggestion:
                    valid_suggestions.append({
                        "name": str(suggestion["name"]),
                        "query": str(suggestion["query"]),
                        "impact": str(suggestion["impact"]).lower(),
                        "description": str(suggestion.get("description", ""))
                    })
                # Handle mutation chains
                elif "name" in suggestion and "mutations" in suggestion and "impact" in suggestion:
                    mutations = suggestion["mutations"]
                    if isinstance(mutations, list):
                        valid_suggestions.append({
                            "name": str(suggestion["name"]),
                            "mutations": [str(m) for m in mutations if isinstance(m, (str, int, float, bool))],
                            "impact": str(suggestion["impact"]).lower(),
                            "description": str(suggestion.get("description", ""))
                        })
                # Handle field tests
                elif "name" in suggestion and "test_values" in suggestion and "impact" in suggestion:
                    test_values = suggestion["test_values"]
                    if isinstance(test_values, list):
                        valid_suggestions.append({
                            "name": str(suggestion["name"]),
                            "test_values": [v for v in test_values if isinstance(v, (str, int, float, bool))],
                            "impact": str(suggestion["impact"]).lower(),
                            "reason": str(suggestion.get("reason", ""))
                        })
                    
            return valid_suggestions
            
        except Exception as e:
            logger.error(f"Unexpected error parsing AI response: {e}", exc_info=True)
            return []
    
    async def get_interesting_fields(
        self,
        type_name: str,
        schema: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Get a list of interesting fields for a given type.
        
        Args:
            type_name: Name of the type to analyze
            schema: The GraphQL schema
            
        Returns:
            List of interesting fields with metadata
        """
        cache_key = f"interesting_fields_{type_name}"
        
        # Check cache first
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        # Prepare the prompt
        prompt = f"""Analyze this GraphQL type and identify the most interesting fields for security testing.
        
Type: {type_name}

Schema:
```
{type_definition}
```

For each field, provide:
- name: The field name
- reason: Why this field is interesting for security testing
- impact: Potential impact if exploited (high/medium/low)
- test_values: List of interesting test values to try

Format your response as a JSON array of objects with these fields.
"""
        # Get the type definition
        type_def = next(
            (t for t in schema.get("__schema", {}).get("types", []) 
             if t.get("name") == type_name),
            None
        )
        
        if not type_def:
            return []
            
        # Format the type definition
        type_definition = self._summarize_type(type_def)
        
        try:
            # Get AI suggestions
            response = await self.prompt_oracle.generate(
                prompt=prompt.format(type_definition=type_definition),
                max_tokens=1000,
                temperature=0.5
            )
            
            # Parse the response
            suggestions = self._parse_ai_response(response)
            
            # Cache the results
            self._cache[cache_key] = suggestions
            
            return suggestions
            
        except Exception as e:
            logger.error(f"Error getting interesting fields: {e}")
            return []

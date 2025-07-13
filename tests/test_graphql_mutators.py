""
Tests for GraphQL type mutators.
"""

import json
import pytest
from typing import Any, Dict, List, Optional

from vulnbuster.modules.graphql.mutators import TypeMutator

# Sample schema for testing
SAMPLE_SCHEMA = {
    "__schema": {
        "types": [
            {
                "name": "Query",
                "kind": "OBJECT",
                "fields": [
                    {
                        "name": "user",
                        "type": {
                            "kind": "OBJECT",
                            "name": "User",
                            "ofType": None
                        },
                        "args": [
                            {
                                "name": "id",
                                "type": {
                                    "kind": "NON_NULL",
                                    "name": None,
                                    "ofType": {
                                        "kind": "SCALAR",
                                        "name": "ID"
                                    }
                                }
                            }
                        ]
                    }
                ]
            },
            {
                "name": "User",
                "kind": "OBJECT",
                "fields": [
                    {
                        "name": "id",
                        "type": {
                            "kind": "NON_NULL",
                            "name": None,
                            "ofType": {
                                "kind": "SCALAR",
                                "name": "ID"
                            }
                        }
                    },
                    {
                        "name": "name",
                        "type": {
                            "kind": "SCALAR",
                            "name": "String"
                        }
                    },
                    {
                        "name": "age",
                        "type": {
                            "kind": "SCALAR",
                            "name": "Int"
                        }
                    },
                    {
                        "name": "isActive",
                        "type": {
                            "kind": "SCALAR",
                            "name": "Boolean"
                        }
                    },
                    {
                        "name": "score",
                        "type": {
                            "kind": "SCALAR",
                            "name": "Float"
                        }
                    }
                ]
            },
            {
                "name": "UserInput",
                "kind": "INPUT_OBJECT",
                "inputFields": [
                    {
                        "name": "name",
                        "type": {
                            "kind": "SCALAR",
                            "name": "String"
                        }
                    },
                    {
                        "name": "age",
                        "type": {
                            "kind": "SCALAR",
                            "name": "Int"
                        }
                    },
                    {
                        "name": "isActive",
                        "type": {
                            "kind": "SCALAR",
                            "name": "Boolean"
                        }
                    }
                ]
            },
            {
                "name": "Status",
                "kind": "ENUM",
                "enumValues": [
                    {"name": "ACTIVE"},
                    {"name": "INACTIVE"},
                    {"name": "SUSPENDED"}
                ]
            },
            {
                "name": "String",
                "kind": "SCALAR"
            },
            {
                "name": "Int",
                "kind": "SCALAR"
            },
            {
                "name": "Float",
                "kind": "SCALAR"
            },
            {
                "name": "Boolean",
                "kind": "SCALAR"
            },
            {
                "name": "ID",
                "kind": "SCALAR"
            },
            {
                "name": "DateTime",
                "kind": "SCALAR"
            },
            {
                "name": "JSON",
                "kind": "SCALAR"
            },
            {
                "name": "Upload",
                "kind": "SCALAR"
            }
        ]
    }
}

@pytest.fixture
def type_mutator() -> TypeMutator:
    """Create a TypeMutator instance with the sample schema."""
    return TypeMutator(schema=SAMPLE_SCHEMA)

def test_type_mutator_initialization(type_mutator: TypeMutator) -> None:
    """Test that the TypeMutator initializes correctly with a schema."""
    assert type_mutator is not None
    assert type_mutator.schema == SAMPLE_SCHEMA

def test_get_type_definition(type_mutator: TypeMutator) -> None:
    """Test getting type definitions from the schema."""
    # Test getting a simple type
    user_type = type_mutator.get_type_definition("User")
    assert user_type is not None
    assert user_type["name"] == "User"
    assert user_type["kind"] == "OBJECT"
    
    # Test getting a non-existent type
    non_existent = type_mutator.get_type_definition("NonExistentType")
    assert non_existent is None

def test_get_scalar_values(type_mutator: TypeMutator) -> None:
    """Test getting mutation values for scalar types."""
    # Test String type
    string_values = type_mutator._get_scalar_values("String")
    assert len(string_values) > 0
    assert any(isinstance(v, str) or v is None for v in string_values)
    
    # Test Int type
    int_values = type_mutator._get_scalar_values("Int")
    assert len(int_values) > 0
    assert any(isinstance(v, (int, float, str)) or v is None for v in int_values)
    
    # Test Float type
    float_values = type_mutator._get_scalar_values("Float")
    assert len(float_values) > 0
    assert any(isinstance(v, (float, int, str)) or v is None for v in float_values)
    
    # Test Boolean type
    bool_values = type_mutator._get_scalar_values("Boolean")
    assert len(bool_values) > 0
    assert any(isinstance(v, (bool, str, int)) or v is None for v in bool_values)
    
    # Test ID type
    id_values = type_mutator._get_scalar_values("ID")
    assert len(id_values) > 0
    assert any(isinstance(v, str) or v is None for v in id_values)
    
    # Test unknown type (should default to String)
    unknown_values = type_mutator._get_scalar_values("UnknownType")
    assert len(unknown_values) > 0
    assert any(isinstance(v, str) or v is None for v in unknown_values)

def test_get_possible_values_scalar(type_mutator: TypeMutator) -> None:
    """Test getting possible values for scalar types."""
    # Test non-null String
    values = type_mutator.get_possible_values("String!")
    assert len(values) > 0
    assert None not in values
    
    # Test list of Int
    values = type_mutator.get_possible_values("[Int]")
    assert len(values) > 0
    assert all(isinstance(v, list) for v in values)

def test_get_possible_values_enum(type_mutator: TypeMutator) -> None:
    """Test getting possible values for enum types."""
    values = type_mutator.get_possible_values("Status")
    assert set(values) == {"ACTIVE", "INACTIVE", "SUSPENDED"}
    
    # Test non-null enum
    values = type_mutator.get_possible_values("Status!")
    assert None not in values

def test_get_possible_values_input_object(type_mutator: TypeMutator) -> None:
    """Test getting possible values for input object types."""
    values = type_mutator.get_possible_values("UserInput")
    assert len(values) > 0
    assert all(isinstance(v, dict) for v in values)
    
    # Check that the input object has the expected fields
    sample = values[0]
    assert all(field in sample for field in ["name", "age", "isActive"])

def test_mutate_arguments(type_mutator: TypeMutator) -> None:
    """Test mutating query arguments."""
    arguments = [
        {
            "name": "id",
            "type": {"name": "ID", "kind": "SCALAR"}
        },
        {
            "name": "name",
            "type": {"name": "String", "kind": "SCALAR"}
        },
        {
            "name": "age",
            "type": {"name": "Int", "kind": "SCALAR"}
        }
    ]
    
    # Test with mutation rate 1.0 (all arguments should be mutated)
    mutated = type_mutator.mutate_arguments(arguments, mutation_rate=1.0)
    assert len(mutated) == len(arguments)
    
    # Test with mutation rate 0.0 (no arguments should be mutated)
    mutated = type_mutator.mutate_arguments(arguments, mutation_rate=0.0)
    assert len(mutated) == 0
    
    # Test with default mutation rate (some arguments may be mutated)
    mutated = type_mutator.mutate_arguments(arguments)
    assert 0 <= len(mutated) <= len(arguments)

def test_generate_input_object(type_mutator: TypeMutator) -> None:
    """Test generating input objects."""
    user_input_type = next(
        t for t in SAMPLE_SCHEMA["__schema"]["types"] 
        if t["name"] == "UserInput"
    )
    
    # Generate an input object
    input_obj = type_mutator._generate_input_object(user_input_type)
    
    # Check that all required fields are present
    assert all(field["name"] in input_obj for field in user_input_type["inputFields"])
    
    # Check that the values are of the correct type
    for field in user_input_type["inputFields"]:
        field_name = field["name"]
        field_type = field["type"]["name"] if field["type"]["kind"] == "SCALAR" else None
        
        if field_name in input_obj:
            value = input_obj[field_name]
            if value is not None:
                if field_type == "String":
                    assert isinstance(value, str)
                elif field_type == "Int":
                    assert isinstance(value, int)
                elif field_type == "Boolean":
                    assert isinstance(value, bool)

def test_mutate_string() -> None:
    """Test string mutation."""
    mutator = TypeMutator()
    values = mutator._mutate_string()
    
    # Check that we have a variety of test cases
    assert "" in values  # Empty string
    assert any("' OR '1'='1" in v if v else False for v in values)  # SQLi
    assert any("<script>" in v if v else False for v in values)  # XSS
    assert any("../../../" in v if v else False for v in values)  # Path traversal
    assert None in values  # Null value

def test_mutate_int() -> None:
    """Test integer mutation."""
    mutator = TypeMutator()
    values = mutator._mutate_int()
    
    # Check that we have a variety of test cases
    assert 0 in values
    assert 1 in values
    assert -1 in values
    assert 2147483647 in values  # 32-bit max
    assert -2147483648 in values  # 32-bit min
    assert None in values  # Null value

def test_mutate_float() -> None:
    """Test float mutation."""
    mutator = TypeMutator()
    values = mutator._mutate_float()
    
    # Check that we have a variety of test cases
    assert 0.0 in values
    assert 1.0 in values
    assert -1.0 in values
    assert float('inf') in values
    assert float('-inf') in values
    assert None in values  # Null value

def test_mutate_boolean() -> None:
    """Test boolean mutation."""
    mutator = TypeMutator()
    values = mutator._mutate_boolean()
    
    # Check that we have a variety of test cases
    assert True in values
    assert False in values
    assert "true" in values
    assert "false" in values
    assert 1 in values
    assert 0 in values
    assert None in values  # Null value

def test_mutate_id() -> None:
    """Test ID mutation."""
    mutator = TypeMutator()
    values = mutator._mutate_id()
    
    # Check that we have a variety of test cases
    assert "1" in values
    assert "0" in values
    assert "-1" in values
    assert "00000000-0000-0000-0000-000000000000" in values  # Zero UUID
    assert None in values  # Null value

def test_mutate_datetime() -> None:
    """Test datetime mutation."""
    from datetime import datetime
    mutator = TypeMutator()
    values = mutator._mutate_datetime()
    
    # Check that we have a variety of test cases
    assert any(isinstance(v, str) or v is None for v in values)
    assert "2020-01-01T00:00:00Z" in values
    assert "invalid-date" in values
    assert "0" in values
    assert None in values  # Null value

def test_mutate_json() -> None:
    """Test JSON mutation."""
    mutator = TypeMutator()
    values = mutator._mutate_json()
    
    # Check that we have a variety of test cases
    assert {} in values
    assert [] in values
    assert {"key": "value"} in values
    assert [1, 2, 3] in values
    assert "{\"key\": \"value\"}" in values
    assert "<script>alert(1)</script>" in values
    assert "' OR '1'='1" in values
    assert None in values  # Null value

def test_mutate_upload() -> None:
    """Test upload mutation."""
    mutator = TypeMutator()
    values = mutator._mutate_upload()
    
    # Check that we have a variety of test cases
    assert len(values) > 0
    assert all(isinstance(v, dict) or v is None for v in values)
    assert any("filename" in v and "content" in v for v in values if v is not None)
    assert any(v is None for v in values)  # Null value

def test_build_type_cache(type_mutator: TypeMutator) -> None:
    """Test that the type cache is built correctly."""
    # The type cache should be populated during initialization
    assert len(type_mutator._type_cache) > 0
    
    # Check that we have the expected types in the cache
    assert "Query" in type_mutator._type_cache
    assert "User" in type_mutator._type_cache
    assert "UserInput" in type_mutator._type_cache
    assert "Status" in type_mutator._type_cache
    
    # Check that internal types are not in the cache
    assert "__Schema" not in type_mutator._type_cache
    assert "__Type" not in type_mutator._type_cache

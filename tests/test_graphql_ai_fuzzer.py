""
Tests for the AI-powered GraphQL fuzzer.
"""

import asyncio
import json
import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from vulnbuster.modules.graphql.fuzzer import GraphQLFuzzer, FuzzResult
from vulnbuster.modules.graphql.client import GraphQLClient
from vulnbuster.modules.graphql.ai_suggestor import AISuggestor

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@pytest.fixture
def mock_client():
    """Create a mock GraphQL client."""
    client = AsyncMock(spec=GraphQLClient)
    client.schema = {
        "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "types": [
                {
                    "name": "Query",
                    "kind": "OBJECT",
                    "fields": [
                        {
                            "name": "users",
                            "type": {"kind": "LIST", "ofType": {"name": "User"}},
                            "args": [{"name": "id", "type": {"name": "ID"}}]
                        },
                        {
                            "name": "user",
                            "type": {"name": "User"},
                            "args": [{"name": "id", "type": {"name": "ID"}}]
                        }
                    ]
                },
                {
                    "name": "Mutation",
                    "kind": "OBJECT",
                    "fields": [
                        {
                            "name": "createUser",
                            "type": {"name": "User"},
                            "args": [{"name": "input", "type": {"name": "UserInput"}}]
                        }
                    ]
                },
                {
                    "name": "User",
                    "kind": "OBJECT",
                    "fields": [
                        {"name": "id", "type": {"name": "ID"}},
                        {"name": "name", "type": {"name": "String"}},
                        {"name": "email", "type": {"name": "String"}},
                        {"name": "isAdmin", "type": {"name": "Boolean"}}
                    ]
                },
                {
                    "name": "UserInput",
                    "kind": "INPUT_OBJECT",
                    "inputFields": [
                        {"name": "name", "type": {"name": "String"}},
                        {"name": "email", "type": {"name": "String"}},
                        {"name": "isAdmin", "type": {"name": "Boolean"}}
                    ]
                }
            ]
        }
    }
    return client

@pytest.fixture
def mock_ai_suggestor():
    """Create a mock AI suggestor."""
    suggestor = MagicMock(spec=AISuggestor)
    
    # Mock query chain suggestions
    query_chains = [
        {
            "name": "Get All Users with Admin Flag",
            "query": "{ users { id name email isAdmin } }",
            "impact": "high",
            "description": "Tests for information disclosure of admin users"
        }
    ]
    
    # Mock mutation chain suggestions
    mutation_chains = [
        {
            "name": "Create Admin User",
            "mutations": [
                "mutation { createUser(input: {name: \"test\", email: \"test@example.com\", isAdmin: true}) { id } }"
            ],
            "impact": "critical",
            "description": "Tests for privilege escalation via direct admin flag setting"
        }
    ]
    
    # Mock field suggestions
    field_suggestions = [
        {
            "name": "isAdmin",
            "reason": "Sensitive boolean flag that could indicate admin access",
            "impact": "high",
            "test_values": [True, False, "true", "false", 1, 0, "1", "0", "yes", "no"]
        }
    ]
    
    # Configure the mock methods
    suggestor.suggest_query_chains.return_value = query_chains
    suggestor.suggest_mutation_chains.return_value = mutation_chains
    suggestor.get_interesting_fields.return_value = field_suggestions
    
    return suggestor

@pytest.fixture
def fuzzer(mock_client, mock_ai_suggestor):
    """Create a GraphQL fuzzer with a mock client and AI suggestor."""
    with patch('vulnbuster.modules.graphql.fuzzer.PromptOracle') as mock_oracle:
        mock_oracle.return_value = MagicMock()
        fuzzer = GraphQLFuzzer(
            client=mock_client,
            enable_ai_suggestions=True,
            max_ai_suggestions=5
        )
        fuzzer.ai_suggestor = mock_ai_suggestor
        return fuzzer

@pytest.mark.asyncio
async def test_ai_suggestor_initialization(fuzzer):
    """Test that the AI suggestor is properly initialized."""
    assert fuzzer.enable_ai_suggestions is True
    assert fuzzer.ai_suggestor is not None

@pytest.mark.asyncio
async def test_generate_ai_suggestions(fuzzer, mock_ai_suggestor):
    """Test generating AI suggestions."""
    # Setup test data
    schema = {"__schema": {"queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"}}}
    
    # Call the method
    await fuzzer._generate_ai_suggestions(schema)
    
    # Verify the AI suggestor was called with the correct parameters
    mock_ai_suggestor.suggest_query_chains.assert_called_once()
    mock_ai_suggestor.suggest_mutation_chains.assert_called_once()
    mock_ai_suggestor.get_interesting_fields.assert_called()

@pytest.mark.asyncio
async def test_add_ai_query_chain_test(fuzzer):
    """Test adding an AI-generated query chain test."""
    # Setup test data
    suggestion = {
        "name": "Test Query",
        "query": "{ test { id } }",
        "impact": "high",
        "description": "Test query"
    }
    
    # Call the method
    fuzzer._add_ai_query_chain_test(suggestion)
    
    # Verify the test was added to the queue or tested_queries
    if hasattr(fuzzer, '_test_queue'):
        assert len(fuzzer._test_queue) > 0
        test_case = fuzzer._test_queue[-1]
        assert test_case["name"] == "AI-Generated Query: Test Query"
        assert test_case["query"] == "{ test { id } }"
    else:
        assert "{ test { id } }" in fuzzer._tested_queries

@pytest.mark.asyncio
async def test_add_ai_mutation_chain_test(fuzzer):
    """Test adding an AI-generated mutation chain test."""
    # Setup test data
    suggestion = {
        "name": "Test Mutation",
        "mutations": ["mutation { test { id } }"],
        "impact": "high",
        "description": "Test mutation"
    }
    
    # Call the method
    fuzzer._add_ai_mutation_chain_test(suggestion)
    
    # Verify the test was added to the queue or tested_queries
    if hasattr(fuzzer, '_test_queue'):
        assert len(fuzzer._test_queue) > 0
        test_case = fuzzer._test_queue[-1]
        assert test_case["name"] == "AI-Generated Mutation 1: Test Mutation"
        assert test_case["query"] == "mutation { test { id } }"
    else:
        assert "mutation { test { id } }" in fuzzer._tested_queries

@pytest.mark.asyncio
async def test_add_ai_field_test(fuzzer):
    """Test adding an AI-generated field test."""
    # Setup test data
    suggestion = {
        "name": "isAdmin",
        "reason": "Sensitive boolean flag",
        "impact": "high",
        "test_values": [True, False]
    }
    
    # Call the method
    fuzzer._add_ai_field_test(suggestion)
    
    # Verify the test was added to the queue or tested_queries
    if hasattr(fuzzer, '_test_queue'):
        assert len(fuzzer._test_queue) >= 2  # At least two test cases for True/False
        test_case = fuzzer._test_queue[-1]
        assert "isAdmin" in test_case["name"]
        assert "isAdmin" in test_case["query"]
    else:
        # Verify the queries were added to tested_queries
        assert any("isAdmin" in q for q in fuzzer._tested_queries)

@pytest.mark.asyncio
async def test_ai_suggestions_in_fuzzing_workflow(fuzzer, mock_client, mock_ai_suggestor):
    """Test that AI suggestions are integrated into the fuzzing workflow."""
    # Setup mocks
    mock_client.introspect_schema.return_value = None
    
    # Run the fuzzer
    vulnerabilities = await fuzzer.fuzz()
    
    # Verify the AI suggestor was used
    mock_ai_suggestor.suggest_query_chains.assert_called_once()
    mock_ai_suggestor.suggest_mutation_chains.assert_called_once()
    mock_ai_suggestor.get_interesting_fields.assert_called()
    
    # Verify vulnerabilities were found (the actual number depends on the mock responses)
    assert isinstance(vulnerabilities, list)

@pytest.mark.asyncio
async def test_ai_suggestor_error_handling(fuzzer, mock_ai_suggestor):
    """Test error handling in the AI suggestion process."""
    # Make the AI suggestor raise an exception
    mock_ai_suggestor.suggest_query_chain.side_effect = Exception("AI service unavailable")
    
    # This should not raise an exception
    try:
        await fuzzer._generate_ai_suggestions({"__schema": {"queryType": {"name": "Query"}}})
    except Exception as e:
        pytest.fail(f"Unexpected exception: {e}")
    
    # The error should be logged but not raised
    assert True  # Test passes if no exception was raised

@pytest.mark.asyncio
async def test_ai_suggestor_disabled():
    """Test that the fuzzer works when AI suggestions are disabled."""
    # Create a fuzzer with AI disabled
    client = AsyncMock(spec=GraphQLClient)
    client.schema = {"__schema": {"queryType": {"name": "Query"}}}
    
    fuzzer = GraphQLFuzzer(
        client=client,
        enable_ai_suggestions=False
    )
    
    # The AI suggestor should not be initialized
    assert fuzzer.ai_suggestor is None
    
    # Running fuzz should not raise an exception
    vulnerabilities = await fuzzer.fuzz()
    assert isinstance(vulnerabilities, list)

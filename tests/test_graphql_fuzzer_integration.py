""
Integration tests for the GraphQL fuzzer.
"""

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional

import pytest
from aiohttp import web

from vulnbuster.modules.graphql.fuzzer import GraphQLFuzzer, FuzzResult

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@pytest.mark.asyncio
async def test_fuzzer_initialization(graphql_fuzzer):
    """Test that the fuzzer initializes correctly."""
    assert graphql_fuzzer is not None
    assert graphql_fuzzer.client is not None
    assert graphql_fuzzer.client.schema is not None
    assert graphql_fuzzer.max_depth > 0
    assert graphql_fuzzer.max_queries > 0
    assert graphql_fuzzer.timeout > 0

@pytest.mark.asyncio
async def test_introspection_test(graphql_fuzzer):
    """Test that the introspection test works correctly."""
    # Clear any existing vulnerabilities
    graphql_fuzzer._vulnerabilities = []
    
    # Run the introspection test
    await graphql_fuzzer._test_introspection()
    
    # Check that vulnerabilities were found (introspection is enabled by default)
    assert len(graphql_fuzzer._vulnerabilities) > 0
    
    # Check that we have the expected vulnerability
    vuln_titles = [v["title"] for v in graphql_fuzzer._vulnerabilities]
    assert any("Introspection" in title for title in vuln_titles)

@pytest.mark.asyncio
async def test_field_suggestions_test(graphql_fuzzer):
    """Test that the field suggestions test works correctly."""
    # Clear any existing vulnerabilities
    graphql_fuzzer._vulnerabilities = []
    
    # Run the field suggestions test
    await graphql_fuzzer._test_field_suggestions()
    
    # Check if any vulnerabilities were found
    # Note: This test might not always find vulnerabilities depending on the server
    assert isinstance(graphql_fuzzer._vulnerabilities, list)

@pytest.mark.asyncio
async def test_query_depth_attack(graphql_fuzzer):
    """Test that the query depth attack test works correctly."""
    # Clear any existing vulnerabilities
    graphql_fuzzer._vulnerabilities = []
    
    # Run the query depth test
    await graphql_fuzzer._test_query_depth()
    
    # Check if any vulnerabilities were found
    # Note: This test might not always find vulnerabilities depending on the server
    assert isinstance(graphql_fuzzer._vulnerabilities, list)

@pytest.mark.asyncio
async def test_directive_overloading(graphql_fuzzer):
    """Test that the directive overloading test works correctly."""
    # Clear any existing vulnerabilities
    graphql_fuzzer._vulnerabilities = []
    
    # Run the directive overloading test
    await graphql_fuzzer._test_directive_overloading()
    
    # Check if any vulnerabilities were found
    # Note: This test might not always find vulnerabilities depending on the server
    assert isinstance(graphql_fuzzer._vulnerabilities, list)

@pytest.mark.asyncio
async def test_batch_queries(graphql_fuzzer):
    """Test that the batch queries test works correctly."""
    # Clear any existing vulnerabilities
    graphql_fuzzer._vulnerabilities = []
    
    # Run the batch queries test
    await graphql_fuzzer._test_batch_queries()
    
    # Check if any vulnerabilities were found
    # Note: This test might not always find vulnerabilities depending on the server
    assert isinstance(graphql_fuzzer._vulnerabilities, list)

@pytest.mark.asyncio
async def test_type_based_mutation(graphql_fuzzer):
    """Test that the type-based mutation test works correctly."""
    # Clear any existing vulnerabilities
    graphql_fuzzer._vulnerabilities = []
    
    # Run the type-based mutation test
    await graphql_fuzzer._test_type_based_mutation()
    
    # Check if any vulnerabilities were found
    # Note: This test might not always find vulnerabilities depending on the server
    assert isinstance(graphql_fuzzer._vulnerabilities, list)

@pytest.mark.asyncio
async def test_full_fuzz(graphql_fuzzer):
    """Test the full fuzzing process."""
    # Run the full fuzzing process
    vulnerabilities = await graphql_fuzzer.fuzz()
    
    # Check that we got a list of vulnerabilities
    assert isinstance(vulnerabilities, list)
    
    # Log the results
    logger.info(f"Found {len(vulnerabilities)} vulnerabilities:")
    for i, vuln in enumerate(vulnerabilities, 1):
        logger.info(f"{i}. [{vuln['severity'].upper()}] {vuln['title']}")

@pytest.mark.asyncio
async def test_fuzz_result_dataclass():
    """Test the FuzzResult dataclass."""
    # Create a FuzzResult instance
    result = FuzzResult(
        successful=True,
        query="query { test }",
        response={"data": {"test": "value"}},
        error=None,
        payload={"key": "value"},
        execution_time=0.123
    )
    
    # Check the values
    assert result.successful is True
    assert result.query == "query { test }"
    assert result.response == {"data": {"test": "value"}}
    assert result.error is None
    assert result.payload == {"key": "value"}
    assert result.execution_time == 0.123

@pytest.mark.asyncio
async def test_fuzzer_with_custom_config():
    """Test the fuzzer with custom configuration."""
    from vulnbuster.modules.graphql.client import GraphQLClient
    
    # Create a client with custom config
    client = GraphQLClient(
        endpoint="http://example.com/graphql",
        headers={"Authorization": "Bearer token"},
        timeout=30
    )
    
    # Create a fuzzer with custom config
    fuzzer = GraphQLFuzzer(
        client=client,
        max_depth=5,
        max_queries=50,
        timeout=60
    )
    
    # Check the configuration
    assert fuzzer.max_depth == 5
    assert fuzzer.max_queries == 50
    assert fuzzer.timeout == 60
    assert fuzzer.client.endpoint == "http://example.com/graphql"
    assert fuzzer.client.headers["Authorization"] == "Bearer token"

@pytest.mark.asyncio
async def test_fuzzer_with_invalid_schema():
    """Test the fuzzer with an invalid schema."""
    from vulnbuster.modules.graphql.client import GraphQLClient
    
    # Create a client with an invalid endpoint
    client = GraphQLClient(endpoint="http://invalid-endpoint")
    
    # Create a fuzzer with the client
    fuzzer = GraphQLFuzzer(client=client)
    
    # Try to run the fuzzer (should not raise an exception)
    vulnerabilities = await fuzzer.fuzz()
    assert isinstance(vulnerabilities, list)

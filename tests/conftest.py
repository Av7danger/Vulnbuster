"""
Pytest configuration and fixtures for GraphQL fuzzer tests.
"""

import asyncio
import json
from typing import Any, Dict, Optional

import pytest
from aiohttp import web
from graphql import (
    GraphQLSchema, GraphQLObjectType, GraphQLField, GraphQLString, 
    GraphQLInt, GraphQLBoolean, GraphQLArgument, GraphQLNonNull,
    GraphQLList, GraphQLEnumType, GraphQLInputObjectType, GraphQLInputField,
    graphql_sync
)

# Sample data for testing
USERS = [
    {"id": "1", "name": "Alice", "age": 30, "isActive": True},
    {"id": "2", "name": "Bob", "age": 25, "isActive": False},
    {"id": "3", "name": "Charlie", "age": 35, "isActive": True}
]

# Define the Status enum
StatusEnum = GraphQLEnumType(
    name="Status",
    values={
        "ACTIVE": {"value": "ACTIVE"},
        "INACTIVE": {"value": "INACTIVE"},
        "SUSPENDED": {"value": "SUSPENDED"}
    }
)

# Define the User type
UserType = GraphQLObjectType(
    name="User",
    fields={
        "id": GraphQLField(GraphQLNonNull(GraphQLString)),
        "name": GraphQLField(GraphQLString),
        "age": GraphQLField(GraphQLInt),
        "isActive": GraphQLField(GraphQLBoolean),
        "status": GraphQLField(
            StatusEnum,
            resolve=lambda obj, info: "ACTIVE" if obj.get("isActive") else "INACTIVE"
        )
    }
)

# Define the UserInput type
UserInputType = GraphQLInputObjectType(
    name="UserInput",
    fields={
        "name": GraphQLInputField(GraphQLString),
        "age": GraphQLInputField(GraphQLInt),
        "isActive": GraphQLInputField(GraphQLBoolean)
    }
)

# Define the Query type
def resolve_user(_, info, id):
    for user in USERS:
        if user["id"] == id:
            return user
    return None

def resolve_users(_, info, status=None):
    if status == "ACTIVE":
        return [u for u in USERS if u["isActive"]]
    elif status == "INACTIVE":
        return [u for u in USERS if not u["isActive"]]
    return USERS

QueryType = GraphQLObjectType(
    name="Query",
    fields={
        "user": GraphQLField(
            UserType,
            args={"id": GraphQLArgument(GraphQLNonNull(GraphQLString))},
            resolve=resolve_user
        ),
        "users": GraphQLField(
            GraphQLList(UserType),
            args={"status": GraphQLArgument(StatusEnum)},
            resolve=resolve_users
        ),
        "echo": GraphQLField(
            GraphQLString,
            args={"input": GraphQLArgument(GraphQLString)},
            resolve=lambda _, info, **args: args.get("input", "")
        )
    }
)

# Define the Mutation type
def resolve_create_user(_, info, user_input):
    new_id = str(len(USERS) + 1)
    user = {"id": new_id, **user_input}
    USERS.append(user)
    return user

MutationType = GraphQLObjectType(
    name="Mutation",
    fields={
        "createUser": GraphQLField(
            UserType,
            args={"input": GraphQLArgument(GraphQLNonNull(UserInputType))},
            resolve=resolve_create_user
        )
    }
)

# Create the schema
schema = GraphQLSchema(query=QueryType, mutation=MutationType)

# GraphQL HTTP view
async def graphql_view(request):
    data = await request.json()
    query = data.get("query")
    variables = data.get("variables", {})
    operation_name = data.get("operationName")
    
    # Execute the GraphQL query
    result = graphql_sync(
        schema,
        query,
        variable_values=variables,
        operation_name=operation_name
    )
    
    # Return the response
    return web.json_response({
        "data": result.data,
        "errors": [
            {"message": str(error), "locations": []}
            for error in (result.errors or [])
        ]
    })

# Health check endpoint
async def health_check(_):
    return web.json_response({"status": "ok"})

# Create the test server
async def create_test_server() -> web.Application:
    app = web.Application()
    app.router.add_post("/graphql", graphql_view)
    app.router.add_get("/health", health_check)
    return app

# Test server fixture
@pytest.fixture
async def test_server(aiohttp_client):
    """Create a test server instance."""
    app = await create_test_server()
    return await aiohttp_client(app)

# GraphQL client fixture
@pytest.fixture
async def graphql_client(test_server):
    """Create a GraphQL client for testing."""
    from vulnbuster.modules.graphql.client import GraphQLClient
    
    client = GraphQLClient(endpoint=f"{test_server.make_url('/graphql')}")
    await client.introspect_schema()  # Ensure schema is loaded
    return client

# GraphQL fuzzer fixture
@pytest.fixture
async def graphql_fuzzer(graphql_client):
    """Create a GraphQL fuzzer for testing."""
    from vulnbuster.modules.graphql.fuzzer import GraphQLFuzzer
    return GraphQLFuzzer(client=graphql_client)

# Type mutator fixture
@pytest.fixture
def type_mutator():
    """Create a TypeMutator instance for testing."""
    from vulnbuster.modules.graphql.mutators import TypeMutator
    return TypeMutator()

# Sample queries for testing
@pytest.fixture
def sample_queries():
    """Sample GraphQL queries for testing."""
    return {
        "get_user": """
        query GetUser($id: ID!) {
            user(id: $id) {
                id
                name
                age
                isActive
            }
        }
        """,
        "get_users": """
        query GetUsers($status: Status) {
            users(status: $status) {
                id
                name
                status
            }
        }
        """,
        "echo": """
        query Echo($input: String) {
            echo(input: $input)
        }
        """,
        "create_user": """
        mutation CreateUser($input: UserInput!) {
            createUser(input: $input) {
                id
                name
                age
                isActive
            }
        }
        """
    }

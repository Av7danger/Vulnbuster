"""
Simplified test for AISuggestor functionality.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock

@pytest.fixture
def mock_prompt_oracle():
    """Create a mock PromptOracle."""
    oracle = MagicMock()
    oracle.generate = AsyncMock(return_value="""
    [
        {
            "name": "Test Query",
            "query": "{ test { id } }",
            "impact": "high",
            "description": "Test query"
        }
    ]
    """)
    return oracle

@pytest.fixture
def ai_suggestor(mock_prompt_oracle):
    """Create an AISuggestor instance with a mock oracle."""
    from vulnbuster.modules.graphql.ai_suggestor import AISuggestor
    return AISuggestor(mock_prompt_oracle)

@pytest.mark.asyncio
async def test_suggest_query_chains(ai_suggestor, mock_prompt_oracle):
    """Test that suggest_query_chains returns expected results."""
    schema = {"__schema": {"types": []}}
    result = await ai_suggestor.suggest_query_chains(schema)
    
    assert len(result) > 0
    assert result[0]["name"] == "Test Query"
    assert "test" in result[0]["query"]
    mock_prompt_oracle.generate.assert_called_once()

if __name__ == "__main__":
    import asyncio
    from vulnbuster.modules.graphql.ai_suggestor import AISuggestor
    
    # Example usage
    class MockOracle:
        async def generate(self, **kwargs):
            return """
            [
                {
                    "name": "Test Query",
                    "query": "{ test { id } }",
                    "impact": "high",
                    "description": "Test query"
                }
            ]
            """
    
    async def main():
        oracle = MockOracle()
        suggestor = AISuggestor(oracle)
        schema = {"__schema": {"types": []}}
        result = await suggestor.suggest_query_chains(schema)
        print("Test Results:")
        print(f"- Found {len(result)} suggestions")
        for i, suggestion in enumerate(result, 1):
            print(f"{i}. {suggestion['name']}: {suggestion['query']}")
    
    asyncio.run(main())

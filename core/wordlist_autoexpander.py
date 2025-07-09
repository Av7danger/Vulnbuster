import asyncio
from typing import List
import random

COMMON_SUBDOMAINS = ['admin', 'dev', 'test', 'staging', 'api', 'beta', 'internal']
COMMON_DIRS = ['admin', 'uploads', 'images', 'js', 'css', 'backup', 'old', 'private']

AI_WORDLIST_PROMPT = (
    "You are an advanced recon assistant. Given a base wordlist, suggest new subdomains and directories "
    "that are likely to exist based on common patterns, target context, and previous findings. "
    "Output only the new words, one per line.\n"
    "Example: base=['login','api'] => ['admin','dev','staging','uploads']"
)

async def ai_expand_wordlist(base: List[str]) -> List[str]:
    # Heuristic: add common subdomains/dirs not already present
    expanded = set(base)
    for word in COMMON_SUBDOMAINS + COMMON_DIRS:
        if word not in expanded and random.random() > 0.3:
            expanded.add(word)
    # In real use, call LLM with AI_WORDLIST_PROMPT
    return list(expanded) 
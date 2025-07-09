import asyncio
import json
from typing import Dict, Any, List, Optional
from pathlib import Path
from datetime import datetime
import hashlib

# --- Memory-Enhanced AI Context Recall ---
class AIMemory:
    def __init__(self, memory_file: str = 'memory/logs.json'):
        self.memory_file = Path(memory_file)
        self.memory_file.parent.mkdir(parents=True, exist_ok=True)
        self.memory_data = self._load_memory()
    
    def _load_memory(self) -> Dict[str, Any]:
        """Load existing memory data"""
        if self.memory_file.exists():
            try:
                with open(self.memory_file, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        return {'sessions': [], 'patterns': {}, 'contexts': {}}
    
    def _save_memory(self):
        """Save memory data to file"""
        with open(self.memory_file, 'w') as f:
            json.dump(self.memory_data, f, indent=2)
    
    def _hash_context(self, context: str) -> str:
        """Create hash for context for efficient lookup"""
        return hashlib.md5(context.encode()).hexdigest()
    
    async def log_interaction(self, prompt: str, response: str, context: Dict[str, Any] = None, 
                             outcome: str = None) -> str:
        """Log AI interaction for future recall"""
        session_id = f"session_{len(self.memory_data['sessions']) + 1}"
        
        interaction = {
            'session_id': session_id,
            'timestamp': datetime.now().isoformat(),
            'prompt': prompt,
            'response': response,
            'context': context or {},
            'outcome': outcome,
            'prompt_hash': self._hash_context(prompt),
            'context_hash': self._hash_context(str(context)) if context else None
        }
        
        self.memory_data['sessions'].append(interaction)
        
        # Extract patterns
        await self._extract_patterns(interaction)
        
        self._save_memory()
        return session_id
    
    async def _extract_patterns(self, interaction: Dict[str, Any]):
        """Extract patterns from interaction for future recall"""
        prompt_lower = interaction['prompt'].lower()
        
        # Extract vulnerability types
        vuln_types = ['xss', 'sqli', 'ssrf', 'lfi', 'rfi', 'xxe', 'csrf', 'idor']
        for vuln_type in vuln_types:
            if vuln_type in prompt_lower:
                if vuln_type not in self.memory_data['patterns']:
                    self.memory_data['patterns'][vuln_type] = []
                self.memory_data['patterns'][vuln_type].append({
                    'prompt_hash': interaction['prompt_hash'],
                    'outcome': interaction['outcome'],
                    'timestamp': interaction['timestamp']
                })
        
        # Extract target types
        target_types = ['web', 'api', 'mobile', 'cloud', 'binary']
        for target_type in target_types:
            if target_type in prompt_lower:
                if target_type not in self.memory_data['patterns']:
                    self.memory_data['patterns'][target_type] = []
                self.memory_data['patterns'][target_type].append({
                    'prompt_hash': interaction['prompt_hash'],
                    'outcome': interaction['outcome'],
                    'timestamp': interaction['timestamp']
                })
    
    async def recall_context(self, current_prompt: str, current_context: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Recall relevant past interactions based on current context"""
        relevant_interactions = []
        current_hash = self._hash_context(current_prompt)
        
        for session in self.memory_data['sessions']:
            relevance_score = 0
            
            # Check prompt similarity
            if session['prompt_hash'] == current_hash:
                relevance_score += 10
            
            # Check context similarity
            if current_context and session['context_hash']:
                if session['context_hash'] == self._hash_context(str(current_context)):
                    relevance_score += 5
            
            # Check keyword overlap
            current_words = set(current_prompt.lower().split())
            session_words = set(session['prompt'].lower().split())
            overlap = len(current_words.intersection(session_words))
            relevance_score += overlap * 0.5
            
            # Check pattern matches
            for pattern_type, patterns in self.memory_data['patterns'].items():
                if pattern_type in current_prompt.lower():
                    for pattern in patterns:
                        if pattern['prompt_hash'] == session['prompt_hash']:
                            relevance_score += 2
            
            if relevance_score > 2:  # Threshold for relevance
                relevant_interactions.append({
                    'session': session,
                    'relevance_score': relevance_score
                })
        
        # Sort by relevance and return top matches
        relevant_interactions.sort(key=lambda x: x['relevance_score'], reverse=True)
        return relevant_interactions[:5]  # Top 5 most relevant
    
    async def enhance_prompt_with_memory(self, prompt: str, context: Dict[str, Any] = None) -> str:
        """Enhance current prompt with relevant past context"""
        relevant_interactions = await self.recall_context(prompt, context)
        
        if not relevant_interactions:
            return prompt
        
        enhanced_prompt = f"{prompt}\n\n"
        enhanced_prompt += "Relevant past context:\n"
        
        for interaction in relevant_interactions:
            session = interaction['session']
            enhanced_prompt += f"- Previous similar case: {session['prompt'][:100]}...\n"
            enhanced_prompt += f"  Outcome: {session['outcome']}\n"
            if session['response']:
                enhanced_prompt += f"  Previous response: {session['response'][:200]}...\n"
            enhanced_prompt += "\n"
        
        enhanced_prompt += "Use this context to improve your response."
        return enhanced_prompt
    
    async def learn_from_outcome(self, session_id: str, outcome: str, success: bool):
        """Update memory with outcome of previous interaction"""
        for session in self.memory_data['sessions']:
            if session['session_id'] == session_id:
                session['outcome'] = outcome
                session['success'] = success
                session['outcome_timestamp'] = datetime.now().isoformat()
                break
        
        self._save_memory()
    
    async def get_memory_stats(self) -> Dict[str, Any]:
        """Get statistics about memory usage"""
        total_interactions = len(self.memory_data['sessions'])
        successful_interactions = len([s for s in self.memory_data['sessions'] if s.get('success', False)])
        
        pattern_stats = {}
        for pattern_type, patterns in self.memory_data['patterns'].items():
            pattern_stats[pattern_type] = len(patterns)
        
        return {
            'total_interactions': total_interactions,
            'successful_interactions': successful_interactions,
            'success_rate': successful_interactions / total_interactions if total_interactions > 0 else 0,
            'pattern_stats': pattern_stats,
            'memory_file_size': self.memory_file.stat().st_size if self.memory_file.exists() else 0
        } 
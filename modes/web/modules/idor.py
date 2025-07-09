import httpx
import logging
import random
import string

class Module:
    def __init__(self, url, payload_engine, analyzer, verbose=False):
        self.url = url
        self.payload_engine = payload_engine
        self.analyzer = analyzer
        self.verbose = verbose
        self.findings = []

    async def run(self):
        # Test for IDOR in URL parameters
        await self.test_numeric_idor()
        await self.test_uuid_idor()
        return self.findings

    async def test_numeric_idor(self):
        # Test numeric ID parameters
        numeric_params = ['id', 'user_id', 'post_id', 'comment_id', 'order_id']
        for param in numeric_params:
            await self.test_parameter_numeric(param)

    async def test_uuid_idor(self):
        # Test UUID parameters
        uuid_params = ['uuid', 'token', 'session_id', 'file_id']
        for param in uuid_params:
            await self.test_parameter_uuid(param)

    async def test_parameter_numeric(self, param):
        # Test with different numeric values
        test_values = [1, 2, 999, 1000, 9999]
        base_url = self.url
        if '?' in base_url:
            base_url += f'&{param}='
        else:
            base_url += f'?{param}='
        
        responses = []
        for value in test_values:
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    resp = await client.get(f'{base_url}{value}')
                    responses.append({
                        'value': value,
                        'status': resp.status_code,
                        'content_length': len(resp.text),
                        'content': resp.text[:100]  # First 100 chars for comparison
                    })
            except Exception:
                pass
        
        # Check for different responses (potential IDOR)
        if len(responses) > 1:
            first_response = responses[0]
            for resp in responses[1:]:
                if resp['status'] != first_response['status'] or resp['content_length'] != first_response['content_length']:
                    self.findings.append({
                        'type': 'IDOR',
                        'url': self.url,
                        'parameter': param,
                        'test_values': [r['value'] for r in responses],
                        'risk': 'high',
                        'cwe': 'CWE-639',
                        'description': f'Potential IDOR in parameter {param}'
                    })
                    break

    async def test_parameter_uuid(self, param):
        # Test with different UUID values
        test_uuids = [
            '00000000-0000-0000-0000-000000000000',
            '11111111-1111-1111-1111-111111111111',
            'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        ]
        base_url = self.url
        if '?' in base_url:
            base_url += f'&{param}='
        else:
            base_url += f'?{param}='
        
        responses = []
        for uuid_val in test_uuids:
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    resp = await client.get(f'{base_url}{uuid_val}')
                    responses.append({
                        'value': uuid_val,
                        'status': resp.status_code,
                        'content_length': len(resp.text)
                    })
            except Exception:
                pass
        
        # Check for different responses
        if len(responses) > 1:
            first_response = responses[0]
            for resp in responses[1:]:
                if resp['status'] != first_response['status'] or resp['content_length'] != first_response['content_length']:
                    self.findings.append({
                        'type': 'IDOR',
                        'url': self.url,
                        'parameter': param,
                        'test_values': [r['value'] for r in responses],
                        'risk': 'high',
                        'cwe': 'CWE-639',
                        'description': f'Potential IDOR in parameter {param}'
                    })
                    break 
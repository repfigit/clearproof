from src.prover.tier_mapping import jurisdiction_matches_vasp, decode_jurisdiction
from src.chain.reader import ChainReader
import asyncio
import hashlib

async def test():
    mock_vasp_info = (b'', '', 'US', '', True, 0)
    signals = ['1', '0'] + ['0'] * 14
    signals[6] = '21843'
    print('Claimed:', decode_jurisdiction(int(signals[6])))
    print('Expected: did:web:test.vasp.com')
    print('Match:', jurisdiction_matches_vasp(signals, 'did:web:test.vasp.com'))
    
    # Test with just the jurisdiction code
    print('Match with US:', jurisdiction_matches_vasp(signals, 'US'))
    
    return True

result = asyncio.run(test())
print('Result:', result)
"""Opt-in actual loopback protocol QA; these are NOT human study records."""
import os
import pytest
from research.lab import Lab

pytestmark = pytest.mark.skipif(os.environ.get("DSOF_RESEARCH_PROTOCOL_TESTS") != "1", reason="Set DSOF_RESEARCH_PROTOCOL_TESTS=1 for temporary localhost listeners")

def test_real_protocol_and_human_audit():
    lab=Lab(audit=True).start()
    try:
        for kind in ('web','ssh','scan'):
            for arm in range(3):
                result=lab.episode(kind,arm,781)
                assert result['status']=='completed', result['error']
                assert result['actions']>0
                assert any(e['class']==kind and e['arm']==arm for e in lab.audit)
        assert lab.counters['ssh_auth']==3
        assert all(e['timestamp']>0 and e['action'] for e in lab.audit)
    finally:
        lab.close()

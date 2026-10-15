"""Explainable profiling and conservative learning from completed live sessions."""
import math
from datetime import datetime, timezone, timedelta

from .dsi import VERSION
from .evaluation import VERSION as EIDP_VERSION, WEIGHTS as EIDP_WEIGHTS

SERVICES = ('web', 'ssh', 'database')


class StrategyOptimizer:
    def __init__(self, store):
        self.store = store

    def profile(self, source, origin):
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat(timespec='milliseconds')
        rows = self.store.list('flows', 1000, src=source, origin=origin)
        rows = [r for r in rows if r['timestamp'] >= cutoff]
        ports = {r.get('dport') for r in rows if r.get('dport') is not None}
        destinations = {r.get('dst') for r in rows if r.get('dst')}
        # These are behavior tiers, not claims about a person's expertise.
        level = 'Advanced' if len(ports) >= 20 and len(destinations) >= 3 else 'Intermediate' if len(ports) >= 5 or len(rows) >= 10 else 'Beginner'
        return {'version': 'behavior-v1', 'level': level, 'window_seconds': 600,
                'observed_flows': len(rows), 'distinct_ports': len(ports),
                'distinct_destinations': len(destinations), 'sample_limit': 1000,
                'meaning': 'Heuristic behavior tier; source addresses may represent multiple users'}

    def rankings(self):
        """SQL joins avoid per-session lookups and count each session once.

        Keep origins and score policies separate. Interrupted, active, legacy
        unprofiled and unattributed sessions cannot train this policy.
        """
        with self.store.lock:
            rows = self.store.conn.execute('''
                SELECT a.data, s.data FROM sessions s JOIN alerts a ON s.alert_id=a.id
                WHERE s.origin='live' AND a.origin='live'
                  AND json_extract(s.data, '$.state')='completed'
            ''').fetchall()
        groups = {}
        import json
        for alert_data, session_data in rows:
            alert, session = json.loads(alert_data), json.loads(session_data)
            dsi = session.get('dsi') or {}
            evaluation = session.get('evaluation') or {}
            if evaluation.get('version') == EIDP_VERSION and evaluation.get('score') is not None:
                dsi = evaluation
            score = dsi.get('score')
            profile = alert.get('attacker_profile') or {}
            service = session.get('service')
            if (profile.get('version') != 'behavior-v1' or not profile.get('level')
                    or service not in SERVICES or dsi.get('version') not in (VERSION,EIDP_VERSION)
                    or dsi.get('provisional', True) or isinstance(score, bool)
                    or not isinstance(score, (int, float)) or not math.isfinite(score)
                    or not 0 <= score <= 100):
                continue
            definition = {'version':dsi['version'],'weights':dsi.get('weights'),'normalizers':dsi.get('normalizers')}
            if dsi['version'] == EIDP_VERSION:
                coverage = dsi.get('coverage') or {}
                definition['scope'] = {'protected_ports':coverage.get('protected_ports'), 'interfaces':coverage.get('interfaces')}
            policy = json.dumps(definition, sort_keys=True)
            key = (alert['classification'], profile['level'], service, policy)
            groups.setdefault(key, []).append(score)
        return [{'attack_type': attack, 'profile': level, 'service': service,
                 'samples': len(scores), 'average_dsi': round(sum(scores)/len(scores), 4),
                 'dsi_policy': json.loads(policy)}
                for (attack, level, service, policy), scores in sorted(groups.items())]

    def choose(self, category, profile, fallback, origin, weights, normalizers, evaluation_scope=None):
        eligible = [r for r in self.rankings()
                      if r['attack_type'] == category and r['profile'] == profile['level']
                      and r['samples'] >= 3]
        eidp = [r for r in eligible if evaluation_scope is not None and r['dsi_policy']['version'] == EIDP_VERSION
                and r['dsi_policy']['weights'] == EIDP_WEIGHTS and r['dsi_policy'].get('scope') == evaluation_scope]
        if any(r['service'] == fallback for r in eidp):
            candidates, basis = eidp, EIDP_VERSION
        else:
            candidates = [r for r in eligible if r['dsi_policy']['version'] == VERSION
                          and r['dsi_policy']['weights'] == weights and r['dsi_policy']['normalizers'] == normalizers]
            basis = VERSION
        # Require comparable evidence for the configured baseline as well as
        # an alternative. No automatic exploration or random deployment.
        baseline = next((r for r in candidates if r['service'] == fallback), None)
        selected, reason = fallback, 'configured_policy'
        if origin == 'live' and baseline:
            best = max(candidates, key=lambda r: (r['average_dsi'], r['service'] == fallback))
            if best['average_dsi'] >= baseline['average_dsi'] + 5:
                selected, reason = best['service'], 'historical_dsi'
        return {'version': 'dsof-feedback-v1', 'selected': selected, 'fallback': fallback,
                'score_basis':basis,
                'reason': reason, 'minimum_samples': 3, 'minimum_improvement': 5,
                'candidates': candidates, 'learning_origin': 'live',
                'meaning': 'Observed engagement comparison; not a causal effectiveness estimate'}

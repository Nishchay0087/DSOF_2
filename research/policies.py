"""One-decision policies. Rewards are in [0, 1]; frozen means no updates."""
import math
import random

NAMES = ('static', 'random', 'rule', 'q_learning', 'epsilon_greedy', 'ucb1')

class Policy:
    def __init__(self, name, seed, epsilon=.1, alpha=.1):
        if name not in NAMES:
            raise ValueError(name)
        self.name, self.epsilon, self.alpha = name, epsilon, alpha
        self.rng = random.Random(seed)
        self.counts = [0]*3
        self.means = [0.]*3
        self.q = [[0.]*3 for _ in range(3)]
        self.q_counts = [[0]*3 for _ in range(3)]

    def best(self, values):
        top = max(values)
        return self.rng.choice([i for i, x in enumerate(values) if x == top])

    def choose(self, bucket, frozen=False):
        if bucket not in (0, 1, 2):
            raise ValueError('Invalid rate bucket')
        if self.name == 'static':
            return 1
        if self.name == 'random':
            return self.rng.randrange(3)
        if self.name == 'rule':
            return bucket  # Explicit experimental rule, not the deployed service mapping.
        if self.name == 'q_learning':
            if not frozen and self.rng.random() < self.epsilon:
                return self.rng.randrange(3)
            return self.best(self.q[bucket])
        if frozen:
            return self.best(self.means)
        if 0 in self.counts:
            return self.counts.index(0)
        if self.name == 'epsilon_greedy':
            return self.rng.randrange(3) if self.rng.random() < self.epsilon else self.best(self.means)
        n = sum(self.counts)
        return self.best([v + math.sqrt(2*math.log(n)/k) for v, k in zip(self.means, self.counts)])

    def update(self, arm, reward, bucket):
        if arm not in (0, 1, 2) or bucket not in (0, 1, 2) or not math.isfinite(reward) or not 0 <= reward <= 1:
            raise ValueError('Invalid observation')
        self.counts[arm] += 1
        self.means[arm] += (reward-self.means[arm])/self.counts[arm]
        self.q[bucket][arm] += self.alpha*(reward-self.q[bucket][arm])
        self.q_counts[bucket][arm] += 1

    def snapshot(self):
        return {'counts': self.counts[:], 'means': self.means[:],
                'q': [r[:] for r in self.q], 'q_counts': [r[:] for r in self.q_counts]}

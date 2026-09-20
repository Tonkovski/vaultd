"""Concise ingest boundaries and a grouped warning digest."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import sys
import time


def log(message, *, error=False):
    print(f'[{time.strftime("%H:%M:%S")}] {message}',
          file=sys.stderr if error else sys.stdout, flush=True)


def size(value):
    for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB'):
        if value < 1024 or unit == 'TiB':
            return f'{value:.1f} {unit}'
        value /= 1024


@dataclass(frozen=True)
class WarningItem:
    category: str
    subject: str
    detail: str
    url: str
    outcome: str


class RunReport:
    def __init__(self):
        self.started = time.monotonic()
        self.completed = 0
        self.failures = 0
        self.status = 'DONE'
        self.active = None
        self.warnings = []
        self._seen = set()

    def collect(self, plan, slug, outcome):
        for warning in plan.warnings:
            item = WarningItem(warning.category, f'{slug} -> {plan.identifier}/{plan.version}',
                               warning.message, f'https://www.gogdb.org/product/{plan.identifier}', outcome)
            if item not in self._seen:
                self._seen.add(item)
                self.warnings.append(item)

    def interrupted(self):
        self.status = 'STOPPED'
        log(f'INTERRUPTED by Ctrl+C: {self.active or "gog_digital ingest"}; '
            'remaining source files stay in intake. Rerun the same command to continue.', error=True)

    def emit(self):
        log(f'{self.status}: {self.completed} release(s) completed; {self.failures} failure(s); '
            f'{len(self.warnings)} warning(s); {time.monotonic() - self.started:.1f}s')
        if not self.warnings:
            return
        groups = defaultdict(list)
        for item in self.warnings:
            groups[item.category].append(item)
        log('WARNINGS (release dates unavailable):', error=True)
        titles = {'no-build': 'No matching GOGDB build',
                  'invalid-date': 'Missing or invalid publication dates',
                  'conflicting-date': 'Conflicting publication dates'}
        for category in sorted(groups):
            items = sorted(groups[category], key=lambda item: (item.subject, item.detail, item.outcome))
            log(f'  {titles.get(category, category)} ({len(items)}):', error=True)
            for item in items:
                detail = '' if category == 'no-build' else f': {item.detail}'
                log(f'    - {item.subject} [{item.outcome}]{detail}; {item.url}', error=True)

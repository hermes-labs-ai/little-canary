"""Exercise the dashboard's live paired-probe rendering without a browser service."""

import shutil
import subprocess
from pathlib import Path

import pytest


def test_dashboard_hides_pooled_rates_for_paired_probe():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is unavailable")

    dashboard = Path(__file__).resolve().parents[1] / "benchmarks" / "dashboard.html"
    script = r"""
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const html = fs.readFileSync(0, 'utf8');
const sourceCode = html.match(/<script>([\s\S]*?)<\/script>/)[1];

function run(paired) {
  const elements = new Map();
  const get = id => {
    if (!elements.has(id)) elements.set(id, {
      style: {}, textContent: '', innerHTML: '', appendChild() {}, className: ''
    });
    return elements.get(id);
  };
  let stream;
  class EventSource { constructor() { stream = this; } }
  vm.runInNewContext(sourceCode, {
    document: { getElementById: get, createElement: () => ({}) }, EventSource
  });
  const result = {
    type: 'result', total: 1, id: 'case', category: 'test', goal: 'test',
    prompt_preview: 'input', stealth: 1, expected_safe: false,
    actual_safe: false, correct: true, scored: true, blocked_by: 'canary',
    risk_score: null, latency_ms: 1, signals: [],
    ...(paired ? { adjudication: 'positive' } : {})
  };
  stream.onmessage({ data: JSON.stringify(result) });
  const summary = paired ? {
    paired_probe: {
      positive: { total: 1, blocked: 1, not_blocked: 0, unscored: 0 },
      benign_control: { total: 0, blocked: 0, not_blocked: 0, unscored: 0 }
    }
  } : {};
  stream.onmessage({ data: JSON.stringify({ type: 'complete', summary }) });
  return get;
}

const paired = run(true);
assert.equal(paired('stats-grid').style.display, 'none');
assert.equal(paired('category-section').style.display, 'none');
assert.equal(paired('secondary-title').textContent, 'Paired probe counts');
assert.match(paired('stealth-chart').textContent, /Positive: 1 blocked/);
assert.doesNotMatch(paired('stealth-chart').textContent, /%/);
assert.doesNotMatch(paired('stealth-chart').innerHTML, /%/);

const standard = run(false);
assert.equal(standard('stats-grid').style.display, '');
assert.equal(standard('category-section').style.display, '');
assert.equal(standard('accuracy').textContent, '100.0%');
assert.match(standard('stealth-chart').innerHTML, /100%/);
"""
    subprocess.run([node, "-e", script], input=dashboard.read_text(), text=True, capture_output=True, check=True)

import test from 'node:test';
import assert from 'node:assert/strict';
import { enforceMaxLength, extractUrlsFromText } from './urlDetect';

test('extractUrlsFromText extracts http/https and shortener URLs without trailing punctuation', () => {
  const input =
    'اضغط هنا http://paypa1-secure.xyz/login، أو راجع bit.ly/3x9demo!';
  assert.deepEqual(extractUrlsFromText(input), [
    'http://paypa1-secure.xyz/login',
    'bit.ly/3x9demo',
  ]);
});

test('enforceMaxLength truncates over 5000 characters and flags truncated', () => {
  const longText = 'أ'.repeat(5050);
  const res = enforceMaxLength(longText, 5000);
  assert.equal(res.truncated, true);
  assert.equal(res.value.length, 5000);

  const shortRes = enforceMaxLength('رسالة قصيرة', 5000);
  assert.equal(shortRes.truncated, false);
  assert.equal(shortRes.value, 'رسالة قصيرة');
});


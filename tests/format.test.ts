import assert from 'node:assert/strict';
import { test } from 'node:test';
// @ts-ignore Node's built-in TypeScript runner requires the extension.
import { colorsToMarkers, markersToColors, mapStrings } from '../app/lib/format.ts';

test('colored spans become markers and back without loss', () => {
  const cases = [
    '<span class="colored c-purple">Danny: hi</span>',
    'a <span class="colored c-red bc-yellow">both</span> b',
    '<span class="colored bc-green">hl</span> and <span class="colored c-blue">blue</span>',
  ];
  for (const html of cases) assert.equal(markersToColors(colorsToMarkers(html)), html);
  assert.equal(colorsToMarkers(cases[0]), '{purple}Danny: hi{/purple}');
  assert.equal(colorsToMarkers(cases[1]), 'a {red bg-yellow}both{/red bg-yellow} b');
});

test('unknown spans and ordinary braces are left alone', () => {
  const odd = '<span class="mention">x</span>';
  assert.equal(colorsToMarkers(odd), odd);
  assert.equal(markersToColors('use {curly} and {red} alone'), 'use {curly} and {red} alone');
  assert.equal(markersToColors('{purple}new{/purple}'), '<span class="colored c-purple">new</span>');
});

test('mapStrings keeps keys and converts values', () => {
  const out = mapStrings({ abc123: '<span class="colored c-pink">p</span>', c: [{ n: 'x' }] }, colorsToMarkers) as any;
  assert.equal(out.abc123, '{pink}p{/pink}');
  assert.equal(out.c[0].n, 'x');
});

import { describe, expect, it } from 'vitest';
import { buildVectors, serialize } from '../conformance/build-vectors.ts';
import { readVectors, runVector } from '../conformance/vectors.ts';

const onDisk = readVectors();

describe('vectors', () => {
  it('are up to date with conformance/build-vectors.ts (run `pnpm vectors`)', () => {
    const built = buildVectors();
    expect(Object.keys(onDisk).sort()).toEqual(Object.keys(built).sort());
    for (const [path, vector] of Object.entries(built)) {
      expect(onDisk[path] && serialize(onDisk[path]), path).toBe(serialize(vector));
    }
  });

  it('cover every kind with valid and invalid cases', () => {
    const groups = new Set(Object.keys(onDisk).map((path) => path.split('/').slice(0, 2).join('/')));
    for (const kind of ['keylog', 'record', 'log', 'checkpoint', 'proof', 'file', 'scape']) {
      expect(groups).toContain(`${kind}/valid`);
      expect(groups).toContain(`${kind}/invalid`);
    }
  });

  for (const [path, vector] of Object.entries(onDisk)) {
    it(path, () => {
      const outcome = runVector(path, vector);
      expect(outcome.pass, outcome.detail).toBe(true);
    });
  }
});

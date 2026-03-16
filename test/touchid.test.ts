import { describe, expect, it } from 'bun:test';

describe('touchid password cache', () => {
  it('should export cachePassword, getCachedPassword, forgetPassword, isTouchIDAvailable', async () => {
    const mod = await import('../src/touchid');
    expect(typeof mod.cachePassword).toBe('function');
    expect(typeof mod.getCachedPassword).toBe('function');
    expect(typeof mod.forgetPassword).toBe('function');
    expect(typeof mod.isTouchIDAvailable).toBe('function');
  });

  it('getLabelForFile should produce deterministic labels', async () => {
    const { getLabelForFile } = await import('../src/touchid');
    const label1 = getLabelForFile('/tmp/test.bep');
    const label2 = getLabelForFile('/tmp/test.bep');
    expect(label1).toBe(label2);
    expect(label1).toMatch(/^bbackup-[a-f0-9]{16}$/);
  });

  it('getLabelForFile should produce different labels for different paths', async () => {
    const { getLabelForFile } = await import('../src/touchid');
    const label1 = getLabelForFile('/tmp/a.bep');
    const label2 = getLabelForFile('/tmp/b.bep');
    expect(label1).not.toBe(label2);
  });

  it('getLabelForFile resolves relative paths to absolute', async () => {
    const { getLabelForFile } = await import('../src/touchid');
    const label1 = getLabelForFile('./test.bep');
    const label2 = getLabelForFile('test.bep');
    expect(label1).toBe(label2);
  });

  it('isTouchIDAvailable returns a boolean', async () => {
    const { isTouchIDAvailable } = await import('../src/touchid');
    expect(typeof isTouchIDAvailable()).toBe('boolean');
  });
});

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { RateLimiter } from '../src/rate-limiter.js';

describe('RateLimiter', () => {
  let limiter: RateLimiter;

  beforeEach(() => {
    vi.useFakeTimers();
    // windowMs=60s, maxFailed=10, blockDuration=300s
    limiter = new RateLimiter(60000, 10, 300000);
  });

  afterEach(() => {
    limiter.destroy();
    vi.useRealTimers();
  });

  it('does not block an unknown IP', () => {
    expect(limiter.isBlocked('1.2.3.4')).toBe(false);
  });

  it('does not block after fewer than threshold failures', () => {
    for (let i = 0; i < 9; i++) {
      expect(limiter.recordFailure('1.2.3.4')).toBe(false);
    }
    expect(limiter.isBlocked('1.2.3.4')).toBe(false);
  });

  it('blocks on the threshold failure and isBlocked returns true', () => {
    for (let i = 0; i < 9; i++) limiter.recordFailure('1.2.3.4');
    expect(limiter.recordFailure('1.2.3.4')).toBe(true);
    expect(limiter.isBlocked('1.2.3.4')).toBe(true);
  });

  it('unblocks after blockDurationMs elapses', () => {
    for (let i = 0; i < 10; i++) limiter.recordFailure('1.2.3.4');
    expect(limiter.isBlocked('1.2.3.4')).toBe(true);
    vi.advanceTimersByTime(300001);
    expect(limiter.isBlocked('1.2.3.4')).toBe(false);
  });

  it('resets count when windowMs elapses without reaching threshold', () => {
    for (let i = 0; i < 5; i++) limiter.recordFailure('1.2.3.4');
    vi.advanceTimersByTime(60001);
    // First failure in new window resets count to 1 — not blocked
    expect(limiter.recordFailure('1.2.3.4')).toBe(false);
    expect(limiter.isBlocked('1.2.3.4')).toBe(false);
  });

  it('tracks multiple IPs independently', () => {
    for (let i = 0; i < 10; i++) limiter.recordFailure('1.1.1.1');
    expect(limiter.isBlocked('1.1.1.1')).toBe(true);
    expect(limiter.isBlocked('2.2.2.2')).toBe(false);
  });

  it('destroy clears the sweep interval (no timer leak)', () => {
    const clearSpy = vi.spyOn(global, 'clearInterval');
    limiter.destroy();
    expect(clearSpy).toHaveBeenCalledOnce();
  });
});

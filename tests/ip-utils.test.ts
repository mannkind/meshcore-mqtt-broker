import { describe, it, expect } from 'vitest';
import type { IncomingMessage } from 'http';
import { getClientIP } from '../src/ip-utils.js';

function mockReq(
  headers: Record<string, string | string[]> = {},
  remoteAddress?: string,
): IncomingMessage {
  return {
    headers,
    socket: { remoteAddress },
  } as unknown as IncomingMessage;
}

describe('getClientIP', () => {
  it.each([
    ['cf-connecting-ip string',  { 'cf-connecting-ip': '1.2.3.4' },             undefined,   '1.2.3.4'],
    ['cf-connecting-ip array',   { 'cf-connecting-ip': ['1.2.3.4', '5.6.7.8'] }, undefined,   '1.2.3.4'],
    ['x-forwarded-for string',  { 'cf-connecting-ip': '1.2.3.4' },             undefined,   '1.2.3.4'],
    ['x-forwarded-for array',   { 'cf-connecting-ip': ['1.2.3.4', '5.6.7.8'] }, undefined,   '1.2.3.4'],
    ['x-real-ip string',  { 'cf-connecting-ip': '1.2.3.4' },             undefined,   '1.2.3.4'],
    ['x-real-ip array',   { 'cf-connecting-ip': ['1.2.3.4', '5.6.7.8'] }, undefined,   '1.2.3.4'],
    ['socket.remoteAddress',     {},                                             '10.0.0.1',  '10.0.0.1'],
    ['unknown when no address',  {},                                             undefined,   'unknown'],
  ] as const)('%s', (_label, headers, remoteAddress, expected) => {
    expect(getClientIP(mockReq(headers as Record<string, string | string[]>, remoteAddress))).toBe(expected);
  });
});

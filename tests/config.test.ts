import { describe, it, expect, afterEach, vi } from 'vitest';

// Spy on process.exit before the module under test loads
vi.spyOn(process, 'exit').mockImplementation((code) => {
  throw new Error(`process.exit(${code})`);
});

// Static import is fine — the load functions read process.env at call time,
// not at module load time, so vi.stubEnv() takes effect before each call.
import {
  loadMqttConfig,
  loadSubscriberConfig,
  loadAbuseConfig,
} from '../src/config.js';

const BASE_ABUSE_ENV: Record<string, string> = {
  ABUSE_DUPLICATE_WINDOW_SIZE: '50',
  ABUSE_DUPLICATE_WINDOW_MS: '10000',
  ABUSE_DUPLICATE_THRESHOLD: '5',
  ABUSE_BUCKET_CAPACITY: '100',
  ABUSE_BUCKET_REFILL_RATE: '10',
  ABUSE_MAX_PACKET_SIZE: '255',
  ABUSE_MAX_TOPICS_PER_DAY: '50',
  ABUSE_ANOMALY_THRESHOLD: '5',
  ABUSE_MAX_IATA_CHANGES_24H: '3',
  ABUSE_TOPIC_HISTORY_SIZE: '100',
  ABUSE_TOPIC_HISTORY_WINDOW_MS: '86400000',
  ABUSE_PERSISTENCE_PATH: ':memory:',
  ABUSE_PERSISTENCE_INTERVAL_MS: '999999999',
  ABUSE_ENFORCEMENT_ENABLED: 'true',
};

function stubMqtt() {
  vi.stubEnv('MQTT_WS_PORT', '8080');
  vi.stubEnv('MQTT_HOST', '0.0.0.0');
  vi.stubEnv('AUTH_EXPECTED_AUDIENCE', 'aud');
  vi.stubEnv('SUBSCRIBER_HMAC_SECRET', 'secret');
}

function stubAbuse(overrides: Record<string, string> = {}) {
  for (const [k, v] of Object.entries({ ...BASE_ABUSE_ENV, ...overrides })) {
    vi.stubEnv(k, v);
  }
}

afterEach(() => { vi.unstubAllEnvs(); });

describe('loadMqttConfig', () => {
  it('returns correct typed object with valid env', () => {
    stubMqtt();
    const cfg = loadMqttConfig();
    expect(cfg.wsPort).toBe(8080);
    expect(cfg.host).toBe('0.0.0.0');
    expect(cfg.expectedAudience).toBe('aud');
    expect(cfg.subscriberHmacSecret).toBe('secret');
  });

  it('exits when MQTT_WS_PORT is missing', () => {
    vi.stubEnv('MQTT_HOST', '0.0.0.0');
    vi.stubEnv('AUTH_EXPECTED_AUDIENCE', 'aud');
    vi.stubEnv('SUBSCRIBER_HMAC_SECRET', 'secret');
    expect(() => loadMqttConfig()).toThrow('process.exit(1)');
  });

  it.each([
    ['zero',        '0'],
    ['above max',   '70000'],
    ['non-numeric', 'abc'],
    ['negative',    '-1'],
  ])('exits when MQTT_WS_PORT is %s', (_label, portValue) => {
    stubMqtt();
    vi.stubEnv('MQTT_WS_PORT', portValue);
    expect(() => loadMqttConfig()).toThrow('process.exit(1)');
  });
});

describe('loadSubscriberConfig', () => {
  it('returns correct value with valid env', () => {
    vi.stubEnv('SUBSCRIBER_MAX_CONNECTIONS_DEFAULT', '10');
    expect(loadSubscriberConfig().defaultMaxConnections).toBe(10);
  });

  it('exits when SUBSCRIBER_MAX_CONNECTIONS_DEFAULT is missing', () => {
    expect(() => loadSubscriberConfig()).toThrow('process.exit(1)');
  });
});

describe('loadAbuseConfig', () => {
  it.each([
    ['true',  true],
    ['false', false],
  ] as const)('parses enforcementEnabled=%s correctly', (value, expected) => {
    stubAbuse({ ABUSE_ENFORCEMENT_ENABLED: value });
    expect(loadAbuseConfig().enforcementEnabled).toBe(expected);
  });

  it.each([
    ['maxDuplicatesPerPacket',  5  ],
    ['duplicateRateThreshold',  0.3],
  ] as const)('applies default for %s when omitted', (field, expected) => {
    stubAbuse();
    expect(loadAbuseConfig()[field]).toBe(expected);
  });

  it('exits when ABUSE_BUCKET_REFILL_RATE is not a valid float', () => {
    stubAbuse({ ABUSE_BUCKET_REFILL_RATE: 'abc' });
    expect(() => loadAbuseConfig()).toThrow('process.exit(1)');
  });

  it('exits when a required abuse var is missing', () => {
    const env = { ...BASE_ABUSE_ENV };
    delete (env as Record<string, string>)['ABUSE_DUPLICATE_WINDOW_SIZE'];
    for (const [k, v] of Object.entries(env)) vi.stubEnv(k, v);
    expect(() => loadAbuseConfig()).toThrow('process.exit(1)');
  });
});

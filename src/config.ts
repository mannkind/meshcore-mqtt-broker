import { randomBytes } from 'crypto';
import { config as dotenvConfig } from 'dotenv';
import { AbuseConfig } from './abuse-detector';
import type { MqttConfig, SubscriberConfig } from './types';

// Load environment variables
dotenvConfig();

// Validate required environment variables
function validateRequiredEnvVars(vars: string[]): void {
  for (const envVar of vars) {
    if (process.env[envVar] === undefined) {
      console.error(`FATAL: Missing required environment variable: ${envVar}`);
      console.error(`Please check your .env file and ensure all variables from .env.example are set.`);
      process.exit(1);
    }
  }
}

function parsePositiveInt(envVar: string, value: string, maxValue?: number): number {
  const n = parseInt(value, 10);
  if (isNaN(n) || n <= 0) {
    console.error(`FATAL: ${envVar} must be a positive integer, got: "${value}"`);
    process.exit(1);
  }
  if (maxValue !== undefined && n > maxValue) {
    console.error(`FATAL: ${envVar} must be <= ${maxValue}, got: ${n}`);
    process.exit(1);
  }
  return n;
}

function parsePositiveFloat(envVar: string, value: string): number {
  const n = parseFloat(value);
  if (isNaN(n) || n <= 0) {
    console.error(`FATAL: ${envVar} must be a positive number, got: "${value}"`);
    process.exit(1);
  }
  return n;
}

// Validate and load MQTT configuration
export function loadMqttConfig(): MqttConfig {
  validateRequiredEnvVars([
    'MQTT_WS_PORT',
    'MQTT_HOST',
    'AUTH_EXPECTED_AUDIENCE',
  ]);

  const subscriberHmacSecret = process.env.SUBSCRIBER_HMAC_SECRET ?? (() => {
    const generated = randomBytes(32).toString('hex');
    console.warn('SUBSCRIBER_HMAC_SECRET not set; using a generated ephemeral secret. Sessions will not survive restarts.');
    return generated;
  })();

  return {
    wsPort: parsePositiveInt('MQTT_WS_PORT', process.env.MQTT_WS_PORT!, 65535),
    host: process.env.MQTT_HOST!,
    expectedAudience: process.env.AUTH_EXPECTED_AUDIENCE!,
    subscriberHmacSecret,
  };
}

// Validate and load subscriber configuration
export function loadSubscriberConfig(): SubscriberConfig {
  validateRequiredEnvVars([
    'SUBSCRIBER_MAX_CONNECTIONS_DEFAULT',
  ]);

  return {
    defaultMaxConnections: parsePositiveInt('SUBSCRIBER_MAX_CONNECTIONS_DEFAULT', process.env.SUBSCRIBER_MAX_CONNECTIONS_DEFAULT!),
  };
}

// Validate and load abuse detection configuration
export function loadAbuseConfig(): AbuseConfig {
  validateRequiredEnvVars([
    'ABUSE_DUPLICATE_WINDOW_SIZE',
    'ABUSE_DUPLICATE_WINDOW_MS',
    'ABUSE_DUPLICATE_THRESHOLD',
    'ABUSE_BUCKET_CAPACITY',
    'ABUSE_BUCKET_REFILL_RATE',
    'ABUSE_MAX_PACKET_SIZE',
    'ABUSE_MAX_TOPICS_PER_DAY',
    'ABUSE_ANOMALY_THRESHOLD',
    'ABUSE_MAX_IATA_CHANGES_24H',
    'ABUSE_TOPIC_HISTORY_SIZE',
    'ABUSE_TOPIC_HISTORY_WINDOW_MS',
    'ABUSE_PERSISTENCE_PATH',
    'ABUSE_PERSISTENCE_INTERVAL_MS',
    'ABUSE_ENFORCEMENT_ENABLED',
  ]);

  return {
    duplicateWindowSize: parsePositiveInt('ABUSE_DUPLICATE_WINDOW_SIZE', process.env.ABUSE_DUPLICATE_WINDOW_SIZE!),
    duplicateWindowMs: parsePositiveInt('ABUSE_DUPLICATE_WINDOW_MS', process.env.ABUSE_DUPLICATE_WINDOW_MS!),
    duplicateThreshold: parsePositiveInt('ABUSE_DUPLICATE_THRESHOLD', process.env.ABUSE_DUPLICATE_THRESHOLD!),
    maxDuplicatesPerPacket: parsePositiveInt('ABUSE_MAX_DUPLICATES_PER_PACKET', process.env.ABUSE_MAX_DUPLICATES_PER_PACKET || '5'),
    duplicateRateThreshold: parsePositiveFloat('ABUSE_DUPLICATE_RATE_THRESHOLD', process.env.ABUSE_DUPLICATE_RATE_THRESHOLD || '0.3'),
    duplicateRateWindowMs: parsePositiveInt('ABUSE_DUPLICATE_RATE_WINDOW_MS', process.env.ABUSE_DUPLICATE_RATE_WINDOW_MS || '300000'),
    bucketCapacity: parsePositiveInt('ABUSE_BUCKET_CAPACITY', process.env.ABUSE_BUCKET_CAPACITY!),
    bucketRefillRate: parsePositiveFloat('ABUSE_BUCKET_REFILL_RATE', process.env.ABUSE_BUCKET_REFILL_RATE!),
    maxPacketSize: parsePositiveInt('ABUSE_MAX_PACKET_SIZE', process.env.ABUSE_MAX_PACKET_SIZE!),
    maxTopicsPerDay: parsePositiveInt('ABUSE_MAX_TOPICS_PER_DAY', process.env.ABUSE_MAX_TOPICS_PER_DAY!),
    anomalyThreshold: parsePositiveInt('ABUSE_ANOMALY_THRESHOLD', process.env.ABUSE_ANOMALY_THRESHOLD!),
    maxIataChanges24h: parsePositiveInt('ABUSE_MAX_IATA_CHANGES_24H', process.env.ABUSE_MAX_IATA_CHANGES_24H!),
    topicHistorySize: parsePositiveInt('ABUSE_TOPIC_HISTORY_SIZE', process.env.ABUSE_TOPIC_HISTORY_SIZE!),
    topicHistoryWindowMs: parsePositiveInt('ABUSE_TOPIC_HISTORY_WINDOW_MS', process.env.ABUSE_TOPIC_HISTORY_WINDOW_MS!),
    persistencePath: process.env.ABUSE_PERSISTENCE_PATH!,
    persistenceIntervalMs: parsePositiveInt('ABUSE_PERSISTENCE_INTERVAL_MS', process.env.ABUSE_PERSISTENCE_INTERVAL_MS!),
    enforcementEnabled: process.env.ABUSE_ENFORCEMENT_ENABLED === 'true',
  };
}


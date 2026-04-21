import type { Client } from 'aedes';
import type { AuthTokenPayload } from '@michaelhart/meshcore-decoder';
import type { Duplex } from 'stream';

export enum ClientType {
  SUBSCRIBER = 'subscriber',
  PUBLISHER = 'publisher',
}

export enum SubscriberRole {
  ADMIN = 1,
  FULL_ACCESS = 2,
  LIMITED = 3,
}

export interface ExtendedStream extends Duplex {
  clientIP?: string;
  authenticated?: boolean;
  client?: ExtendedClient;
  close?: (...args: unknown[]) => void;
}

export interface ExtendedClient extends Omit<Client, 'conn'> {
  conn: ExtendedStream;
  publicKey?: string;
  tokenPayload?: AuthTokenPayload;
  clientType?: ClientType;
  username?: string;
  role?: SubscriberRole;
  connectedAt?: number;
  stream?: ExtendedStream;
}

export interface TrustMetricsSnapshot {
  status: 'allowed' | 'muted' | 'would_mute';
  enforcement_enabled: boolean;
  totalPacketsReceived: number;
  totalPacketsSilenced: number;
  duplicateCount: number;
  anomalyCount: number;
  anomalies: { type: string; details: string; timestamp: number }[];
  peakRateObserved: number;
  tokenBucket: { tokens: number; capacity: number };
  iataTracking: {
    currentIata?: string;
    iataChangeCount24h: number;
    iataHistory: string[];
  };
  clockTracking: {
    estimatedOffset?: number;
    erraticJumpCount: number;
    lastDeviceTimestamp?: number;
    clockQuality: 'stable' | 'syncing' | 'erratic';
  };
  recentIPs: { ip: string; connectionCount: number; lastSeen: number }[];
}

export interface MqttConfig {
  wsPort: number;
  host: string;
  expectedAudience: string;
  subscriberHmacSecret: string;
}

export interface SubscriberConfig {
  defaultMaxConnections: number;
}

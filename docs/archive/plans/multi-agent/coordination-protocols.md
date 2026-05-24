# Secure Coordination Protocols Specification

## Problem Statement

Multi-agent systems require secure communication channels for task delegation, data exchange, and coordination. Without secure protocols:

1. **Message Tampering**: Adversaries modify messages between agents
2. **Replay Attacks**: Old messages replayed to cause incorrect behavior
3. **Eavesdropping**: Sensitive data intercepted in transit
4. **Impersonation**: Malicious agents inject messages as trusted agents
5. **Denial of Service**: Message flooding disrupts coordination

This specification defines the cryptographic protocols and message formats for secure agent-to-agent communication.

## Threat Model

### Attack Scenarios

#### Scenario 1: Man-in-the-Middle

```
Agent A ----------[Message]----------> Agent B
                     ^
                     |
              Attacker intercepts,
              modifies message
```

**Mitigation**: End-to-end encryption with authenticated key exchange

#### Scenario 2: Message Replay

```
Time T: Agent A sends task to Agent B
Time T+1: Task completed
Time T+2: Attacker replays original task message
Agent B executes task again
```

**Mitigation**: Message nonces, sequence numbers, timestamp validation

#### Scenario 3: Protocol Downgrade

```
Agent A supports: TLS 1.3, TLS 1.2
Agent B supports: TLS 1.3, TLS 1.2, TLS 1.1

Attacker forces TLS 1.1 negotiation (vulnerable)
```

**Mitigation**: Minimum protocol version enforcement, capability announcement signing

#### Scenario 4: Denial of Service via Message Flood

```
Malicious Agent ----[1000s of messages/sec]----> Target Agent
                                                      |
                                                      v
                                              Resource exhaustion
```

**Mitigation**: Rate limiting, connection limits, priority queuing

### Threat Actors

| Actor | Capability | Goal |
|-------|------------|------|
| Network Attacker | Intercept/modify network traffic | Steal data, disrupt coordination |
| Compromised Agent | Send arbitrary messages | Manipulate other agents |
| Rogue Orchestrator | Inject fake agents | Control coordination |
| Insider | Access to keys | Decrypt historic communications |

## Architecture

### Protocol Stack

```
+------------------------------------------------------------------+
|                    Application Layer                              |
|  +------------------------------------------------------------+  |
|  | Coordination Messages (Task, Result, Event, Heartbeat)      |  |
|  +------------------------------------------------------------+  |
+------------------------------------------------------------------+
|                    Framing Layer                                  |
|  +------------------------------------------------------------+  |
|  | Length-Prefixed CBOR Frames                                 |  |
|  | Sequence Numbers, Timestamps                                |  |
|  +------------------------------------------------------------+  |
+------------------------------------------------------------------+
|                    Encryption Layer                               |
|  +------------------------------------------------------------+  |
|  | AES-256-GCM (data) | ChaCha20-Poly1305 (alternative)       |  |
|  | Per-message nonce | Additional Authenticated Data (AAD)    |  |
|  +------------------------------------------------------------+  |
+------------------------------------------------------------------+
|                    Key Exchange Layer                             |
|  +------------------------------------------------------------+  |
|  | X25519 ECDH | Optional: Noise Protocol                      |  |
|  | Key confirmation | Forward secrecy                          |  |
|  +------------------------------------------------------------+  |
+------------------------------------------------------------------+
|                    Authentication Layer                           |
|  +------------------------------------------------------------+  |
|  | Mutual TLS | Certificate verification                       |  |
|  | Agent identity binding | Delegation token verification     |  |
|  +------------------------------------------------------------+  |
+------------------------------------------------------------------+
|                    Transport Layer                                |
|  +------------------------------------------------------------+  |
|  | TCP/TLS 1.3 | QUIC (optional)                              |  |
|  +------------------------------------------------------------+  |
+------------------------------------------------------------------+
```

### Message Flow

```
+-------------+                                    +-------------+
| Agent A     |                                    | Agent B     |
+------+------+                                    +------+------+
       |                                                  |
       | 1. TLS ClientHello                              |
       |------------------------------------------------->|
       |                                                  |
       | 2. TLS ServerHello + Certificate                |
       |<-------------------------------------------------|
       |                                                  |
       | 3. Certificate + Finished                       |
       |------------------------------------------------->|
       |                                                  |
       | 4. Finished                                      |
       |<-------------------------------------------------|
       |                                                  |
       |===== TLS Session Established =====               |
       |                                                  |
       | 5. ChannelInit (agent identity, capabilities)   |
       |------------------------------------------------->|
       |                                                  |
       | 6. ChannelAccept (agent identity, capabilities) |
       |<-------------------------------------------------|
       |                                                  |
       |===== Coordination Channel Ready =====            |
       |                                                  |
       | 7. Task { id, type, payload, delegation_token } |
       |------------------------------------------------->|
       |                                                  |
       | 8. TaskAck { task_id, accepted: true }          |
       |<-------------------------------------------------|
       |                                                  |
       | 9. TaskResult { task_id, result, evidence }     |
       |<-------------------------------------------------|
       |                                                  |
       | 10. ResultAck { task_id }                       |
       |------------------------------------------------->|
       |                                                  |
```

### Task Lifecycle with Delegation

```
+-------------+     +------------------+     +-------------+
| Agent A     |     | Clawdstrike      |     | Agent B     |
| (Requester) |     | Policy Engine    |     | (Executor)  |
+------+------+     +--------+---------+     +------+------+
       |                     |                      |
       | 1. Create delegation token                 |
       |    (for Agent B to access A's resources)   |
       |-------------------------------------------->
       |                     |                      |
       | 2. Task { taskId, delegationToken }       |
       |------------------------------------------->|
       |                     |                      |
       |                     | 3. Verify delegation |
       |                     |<---------------------|
       |                     |                      |
       |                     | 4. Token valid       |
       |                     |--------------------->|
       |                     |                      |
       |                     |        5. Access A's |
       |                     |           resources  |
       |                     |<---------------------|
       |                     |                      |
       |                     | 6. Policy check      |
       |                     |    (delegation OK)   |
       |                     |--------------------->|
       |                     |                      |
       | 7. TaskResult { evidence, signature }     |
       |<-------------------------------------------|
       |                     |                      |
       | 8. Audit events correlated by traceId     |
       |<--------------------|--------------------->|
       |                     |                      |
```

### Error Handling Flow

```
+-------------+                              +-------------+
| Agent A     |                              | Agent B     |
+------+------+                              +------+------+
       |                                            |
       | Task { taskId, timeout: 30000 }           |
       |------------------------------------------->|
       |                                            |
       | TaskAck { accepted: true }                |
       |<-------------------------------------------|
       |                                            |
       |        [Agent B encounters error]         |
       |                                            |
       | TaskResult { success: false, error: "..." }
       |<-------------------------------------------|
       |                                            |
       | ResultAck { taskId }                      |
       |------------------------------------------->|
       |                                            |

Timeout Scenario:
=================
       |                                            |
       | Task { taskId, timeout: 5000 }            |
       |------------------------------------------->|
       |                                            |
       | TaskAck { accepted: true }                |
       |<-------------------------------------------|
       |                                            |
       |  [5000ms passes without result]           |
       |                                            |
       | [Agent A raises TimeoutError]             |
       | [Logs task.timeout audit event]           |
       |                                            |
       | (Optional) Cancel { taskId }              |
       |------------------------------------------->|
       |                                            |
```

### Channel Multiplexing

```
+------------------------------------------------------------------+
|                    Coordination Channel                           |
+------------------------------------------------------------------+
|                                                                   |
|  +----------------+  +----------------+  +----------------+       |
|  | Stream 0       |  | Stream 1       |  | Stream 2       |       |
|  | (Control)      |  | (Tasks)        |  | (Events)       |       |
|  +----------------+  +----------------+  +----------------+       |
|                                                                   |
|  Stream Header: [Stream ID (2B)] [Flags (1B)] [Length (3B)]      |
|                                                                   |
+------------------------------------------------------------------+
```

### Protocol State Machine

```
+------------------------------------------------------------------+
|                    Channel State Machine                          |
+------------------------------------------------------------------+

    +-----------+
    | CLOSED    |
    +-----+-----+
          |
          | connect() / listen()
          v
    +-----------+       TLS handshake failed
    | TLS_INIT  |----------------------------> [CLOSED]
    +-----+-----+
          |
          | TLS handshake complete
          v
    +-----------+       channel_init timeout
    | HANDSHAKE |----------------------------> [CLOSED]
    +-----+-----+
          |
          | channel_accept received, keys derived
          v
    +-----------+
    | READY     |<--+
    +-----+-----+   |
          |         | heartbeat_ack received
          |         |
          +---------+
          |
          | heartbeat timeout / error / close()
          v
    +-----------+
    | CLOSING   |
    +-----+-----+
          |
          | channel_close sent/received
          v
    +-----------+
    | CLOSED    |
    +-----------+

Task State Machine (within READY state):
=========================================

    +-----------+
    | PENDING   |  task sent, awaiting ack
    +-----+-----+
          |
          | task_ack(accepted=true)    task_ack(accepted=false)
          |------------------------+----------------------> [REJECTED]
          v                        |
    +-----------+                  |
    | EXECUTING |                  |
    +-----+-----+                  |
          |                        |
          | task_result            | timeout
          |------------------------+----------------------> [TIMEOUT]
          v
    +-----------+
    | COMPLETED |
    +-----------+

Message Sequence Numbers:
=========================
- Each direction maintains independent sequence counter
- Starts at 0, increments by 1 per message
- Gaps indicate message loss (trigger retransmit or error)
- Duplicates (same seq) are ignored
- Receiver tracks: expected_seq, highest_received_seq
- Window size: configurable (default 1000 outstanding messages)
```

## API Design

### TypeScript Interface

```typescript
import { AgentIdentity } from './identity-attestation';
import { DelegationToken } from './delegation-tokens';

/**
 * Coordination message types
 */
export type MessageType =
  | 'channel_init'
  | 'channel_accept'
  | 'channel_close'
  | 'task'
  | 'task_ack'
  | 'task_result'
  | 'result_ack'
  | 'event'
  | 'heartbeat'
  | 'heartbeat_ack'
  | 'error';

/**
 * Base message structure
 */
export interface Message {
  /** Message type */
  type: MessageType;

  /** Unique message ID */
  id: string;

  /** Sequence number within channel */
  seq: number;

  /** Timestamp (Unix milliseconds) */
  timestamp: number;

  /** Trace ID for correlation */
  traceId?: string;

  /** Sender agent ID */
  from: AgentId;

  /** Recipient agent ID */
  to: AgentId;
}

/**
 * Channel initialization message
 */
export interface ChannelInitMessage extends Message {
  type: 'channel_init';
  payload: {
    /** Protocol version */
    protocolVersion: string;
    /** Sender's identity */
    identity: AgentIdentitySummary;
    /** Sender's capabilities */
    capabilities: Capability[];
    /** Supported encryption algorithms */
    supportedCiphers: string[];
    /** Key exchange material */
    keyExchange: KeyExchangeData;
  };
}

/**
 * Channel accept message
 */
export interface ChannelAcceptMessage extends Message {
  type: 'channel_accept';
  payload: {
    /** Protocol version (agreed) */
    protocolVersion: string;
    /** Responder's identity */
    identity: AgentIdentitySummary;
    /** Responder's capabilities */
    capabilities: Capability[];
    /** Selected cipher */
    selectedCipher: string;
    /** Key exchange material */
    keyExchange: KeyExchangeData;
  };
}

/**
 * Task message
 */
export interface TaskMessage extends Message {
  type: 'task';
  payload: {
    /** Task ID */
    taskId: string;
    /** Task type */
    taskType: string;
    /** Task parameters */
    parameters: Record<string, unknown>;
    /** Priority (0 = highest) */
    priority?: number;
    /** Timeout in milliseconds */
    timeout?: number;
    /** Delegation token granting permissions */
    delegationToken?: string;
    /** Required capabilities for execution */
    requiredCapabilities?: Capability[];
    /** Context from parent task */
    parentContext?: TaskContext;
  };
}

/**
 * Task acknowledgment
 */
export interface TaskAckMessage extends Message {
  type: 'task_ack';
  payload: {
    /** Task ID being acknowledged */
    taskId: string;
    /** Whether task was accepted */
    accepted: boolean;
    /** Rejection reason (if not accepted) */
    reason?: string;
    /** Estimated completion time */
    estimatedCompletionMs?: number;
  };
}

/**
 * Task result message
 */
export interface TaskResultMessage extends Message {
  type: 'task_result';
  payload: {
    /** Task ID */
    taskId: string;
    /** Whether task succeeded */
    success: boolean;
    /** Result data */
    result?: unknown;
    /** Error message (if failed) */
    error?: string;
    /** Execution evidence (for audit) */
    evidence?: ExecutionEvidence;
    /** Resource usage */
    resourceUsage?: ResourceUsage;
  };
}

/**
 * Event message (for pub/sub style coordination)
 */
export interface EventMessage extends Message {
  type: 'event';
  payload: {
    /** Event type */
    eventType: string;
    /** Event data */
    data: Record<string, unknown>;
    /** Event source (original producer) */
    source: AgentId;
    /** Event time */
    eventTime: number;
  };
}

/**
 * Heartbeat message
 */
export interface HeartbeatMessage extends Message {
  type: 'heartbeat';
  payload: {
    /** Sequence for RTT calculation */
    pingSeq: number;
    /** Current load (0-100) */
    load?: number;
    /** Active task count */
    activeTasks?: number;
  };
}

/**
 * Agent identity summary (for channel setup)
 */
export interface AgentIdentitySummary {
  id: AgentId;
  publicKey: string; // Base64-encoded
  certificateFingerprint: string;
  metadata: {
    name: string;
    role?: string;
  };
}

/**
 * Key exchange data (X25519)
 */
export interface KeyExchangeData {
  /** Ephemeral public key */
  publicKey: string; // Base64-encoded
  /** Key ID for tracking */
  keyId: string;
}

/**
 * Task context (for nested tasks)
 */
export interface TaskContext {
  /** Parent task ID */
  parentTaskId: string;
  /** Original requester */
  originalRequester: AgentId;
  /** Delegation chain */
  delegationChain: string[];
  /** Remaining timeout */
  remainingTimeoutMs?: number;
}

/**
 * Execution evidence
 */
export interface ExecutionEvidence {
  /** Start time */
  startTime: number;
  /** End time */
  endTime: number;
  /** Actions performed */
  actions: ExecutionAction[];
  /** Signature over evidence */
  signature: string;
}

/**
 * Execution action record
 */
export interface ExecutionAction {
  /** Action type */
  type: string;
  /** Action target */
  target: string;
  /** Action result */
  result: 'success' | 'failure';
  /** Timestamp */
  timestamp: number;
}

/**
 * Coordination channel
 */
export class CoordinationChannel {
  private ws: WebSocket | null = null;
  private identity: AgentIdentity;
  private peerIdentity: AgentIdentitySummary | null = null;
  private sessionKey: Uint8Array | null = null;
  private sequenceNumber: number = 0;
  private pendingTasks: Map<string, TaskPromise> = new Map();
  private messageHandlers: Map<MessageType, MessageHandler[]> = new Map();
  private config: ChannelConfig;

  constructor(identity: AgentIdentity, config: ChannelConfig) {
    this.identity = identity;
    this.config = config;
  }

  /**
   * Connect to another agent
   */
  async connect(targetUrl: string, targetAgentId: AgentId): Promise<void> {
    // Establish TLS connection
    this.ws = new WebSocket(targetUrl, {
      cert: this.identity.certificate,
      key: this.config.privateKey,
      ca: this.config.trustedCAs,
      rejectUnauthorized: true,
    });

    await this.waitForOpen();

    // Perform channel initialization
    await this.performHandshake(targetAgentId);
  }

  /**
   * Accept incoming connection
   */
  async accept(ws: WebSocket): Promise<void> {
    this.ws = ws;

    // Wait for channel init
    const initMessage = await this.receiveMessage('channel_init');
    const init = initMessage as ChannelInitMessage;

    // Verify peer identity
    await this.verifyPeerIdentity(init.payload.identity);

    // Perform key exchange
    const { sharedSecret, responseKeyExchange } = await this.performKeyExchange(
      init.payload.keyExchange
    );
    this.sessionKey = sharedSecret;
    this.peerIdentity = init.payload.identity;

    // Send accept
    await this.sendMessage({
      type: 'channel_accept',
      id: this.generateMessageId(),
      seq: this.sequenceNumber++,
      timestamp: Date.now(),
      from: this.identity.id,
      to: init.from,
      payload: {
        protocolVersion: '1.0.0',
        identity: this.getIdentitySummary(),
        capabilities: this.identity.getCapabilities(),
        selectedCipher: 'AES-256-GCM',
        keyExchange: responseKeyExchange,
      },
    } as ChannelAcceptMessage);
  }

  /**
   * Send a task to the peer agent
   */
  async sendTask(task: TaskRequest): Promise<TaskResult> {
    const taskId = this.generateTaskId();

    const taskMessage: TaskMessage = {
      type: 'task',
      id: this.generateMessageId(),
      seq: this.sequenceNumber++,
      timestamp: Date.now(),
      traceId: task.traceId,
      from: this.identity.id,
      to: this.peerIdentity!.id,
      payload: {
        taskId,
        taskType: task.type,
        parameters: task.parameters,
        priority: task.priority,
        timeout: task.timeout,
        delegationToken: task.delegationToken?.toString(),
        requiredCapabilities: task.requiredCapabilities,
        parentContext: task.parentContext,
      },
    };

    // Create promise for result
    const taskPromise = new TaskPromise(taskId, task.timeout);
    this.pendingTasks.set(taskId, taskPromise);

    try {
      // Send task
      await this.sendMessage(taskMessage);

      // Wait for ack
      const ack = await taskPromise.waitForAck();
      if (!ack.payload.accepted) {
        throw new Error(`Task rejected: ${ack.payload.reason}`);
      }

      // Wait for result
      const result = await taskPromise.waitForResult();

      // Send result ack
      await this.sendMessage({
        type: 'result_ack',
        id: this.generateMessageId(),
        seq: this.sequenceNumber++,
        timestamp: Date.now(),
        from: this.identity.id,
        to: this.peerIdentity!.id,
        payload: { taskId },
      });

      return {
        taskId,
        success: result.payload.success,
        result: result.payload.result,
        error: result.payload.error,
        evidence: result.payload.evidence,
      };
    } finally {
      this.pendingTasks.delete(taskId);
    }
  }

  /**
   * Register a task handler
   */
  onTask(
    taskType: string,
    handler: (task: TaskMessage) => Promise<TaskResultPayload>
  ): void {
    const wrapper = async (message: Message) => {
      const taskMessage = message as TaskMessage;
      if (taskMessage.payload.taskType !== taskType) return;

      // Send ack
      await this.sendMessage({
        type: 'task_ack',
        id: this.generateMessageId(),
        seq: this.sequenceNumber++,
        timestamp: Date.now(),
        from: this.identity.id,
        to: message.from,
        payload: {
          taskId: taskMessage.payload.taskId,
          accepted: true,
        },
      } as TaskAckMessage);

      // Execute handler
      try {
        const result = await handler(taskMessage);

        // Send result
        await this.sendMessage({
          type: 'task_result',
          id: this.generateMessageId(),
          seq: this.sequenceNumber++,
          timestamp: Date.now(),
          from: this.identity.id,
          to: message.from,
          payload: {
            taskId: taskMessage.payload.taskId,
            ...result,
          },
        } as TaskResultMessage);
      } catch (error) {
        // Send error result
        await this.sendMessage({
          type: 'task_result',
          id: this.generateMessageId(),
          seq: this.sequenceNumber++,
          timestamp: Date.now(),
          from: this.identity.id,
          to: message.from,
          payload: {
            taskId: taskMessage.payload.taskId,
            success: false,
            error: error instanceof Error ? error.message : String(error),
          },
        } as TaskResultMessage);
      }
    };

    this.addHandler('task', wrapper);
  }

  /**
   * Publish an event
   */
  async publishEvent(eventType: string, data: Record<string, unknown>): Promise<void> {
    await this.sendMessage({
      type: 'event',
      id: this.generateMessageId(),
      seq: this.sequenceNumber++,
      timestamp: Date.now(),
      from: this.identity.id,
      to: this.peerIdentity!.id,
      payload: {
        eventType,
        data,
        source: this.identity.id,
        eventTime: Date.now(),
      },
    } as EventMessage);
  }

  /**
   * Subscribe to events
   */
  onEvent(eventType: string, handler: (event: EventMessage) => void): void {
    this.addHandler('event', (message) => {
      const event = message as EventMessage;
      if (event.payload.eventType === eventType) {
        handler(event);
      }
    });
  }

  /**
   * Close the channel
   */
  async close(): Promise<void> {
    if (this.ws) {
      await this.sendMessage({
        type: 'channel_close',
        id: this.generateMessageId(),
        seq: this.sequenceNumber++,
        timestamp: Date.now(),
        from: this.identity.id,
        to: this.peerIdentity!.id,
        payload: {},
      });

      this.ws.close();
      this.ws = null;
    }
  }

  private async sendMessage(message: Message): Promise<void> {
    if (!this.ws || !this.sessionKey) {
      throw new Error('Channel not established');
    }

    // Serialize message
    const plaintext = cbor.encode(message);

    // Encrypt
    const nonce = this.generateNonce();
    const aad = this.buildAAD(message);
    const ciphertext = await this.encrypt(plaintext, nonce, aad);

    // Frame: [length (4B)] [nonce (12B)] [ciphertext]
    const frame = new Uint8Array(4 + 12 + ciphertext.length);
    const view = new DataView(frame.buffer);
    view.setUint32(0, 12 + ciphertext.length, false);
    frame.set(nonce, 4);
    frame.set(ciphertext, 16);

    this.ws.send(frame);
  }

  private async receiveMessage(expectedType?: MessageType): Promise<Message> {
    return new Promise((resolve, reject) => {
      const handler = async (event: MessageEvent) => {
        try {
          const frame = new Uint8Array(event.data);
          const view = new DataView(frame.buffer);
          const length = view.getUint32(0, false);
          const nonce = frame.slice(4, 16);
          const ciphertext = frame.slice(16, 4 + length);

          // Decrypt
          const plaintext = await this.decrypt(ciphertext, nonce);
          const message = cbor.decode(plaintext) as Message;

          // Validate
          this.validateMessage(message);

          if (expectedType && message.type !== expectedType) {
            return; // Not the message we're waiting for
          }

          this.ws!.removeEventListener('message', handler);
          resolve(message);
        } catch (error) {
          reject(error);
        }
      };

      this.ws!.addEventListener('message', handler);
    });
  }

  private async performHandshake(targetAgentId: AgentId): Promise<void> {
    // Generate ephemeral key pair
    const ephemeralKeyPair = await this.generateEphemeralKeyPair();

    // Send channel init
    const initMessage: ChannelInitMessage = {
      type: 'channel_init',
      id: this.generateMessageId(),
      seq: this.sequenceNumber++,
      timestamp: Date.now(),
      from: this.identity.id,
      to: targetAgentId,
      payload: {
        protocolVersion: '1.0.0',
        identity: this.getIdentitySummary(),
        capabilities: this.identity.getCapabilities(),
        supportedCiphers: ['AES-256-GCM', 'ChaCha20-Poly1305'],
        keyExchange: {
          publicKey: base64.encode(ephemeralKeyPair.publicKey),
          keyId: this.generateKeyId(),
        },
      },
    };

    // Send unencrypted (TLS provides transport security)
    this.ws!.send(cbor.encode(initMessage));

    // Wait for accept
    const acceptEvent = await this.waitForMessage('channel_accept');
    const accept = cbor.decode(acceptEvent.data) as ChannelAcceptMessage;

    // Verify peer identity
    await this.verifyPeerIdentity(accept.payload.identity);

    // Complete key exchange
    const peerPublicKey = base64.decode(accept.payload.keyExchange.publicKey);
    this.sessionKey = await this.deriveSessionKey(
      ephemeralKeyPair.privateKey,
      peerPublicKey
    );
    this.peerIdentity = accept.payload.identity;
  }

  private async performKeyExchange(
    peerKeyExchange: KeyExchangeData
  ): Promise<{ sharedSecret: Uint8Array; responseKeyExchange: KeyExchangeData }> {
    const ephemeralKeyPair = await this.generateEphemeralKeyPair();
    const peerPublicKey = base64.decode(peerKeyExchange.publicKey);

    const sharedSecret = await this.deriveSessionKey(
      ephemeralKeyPair.privateKey,
      peerPublicKey
    );

    return {
      sharedSecret,
      responseKeyExchange: {
        publicKey: base64.encode(ephemeralKeyPair.publicKey),
        keyId: this.generateKeyId(),
      },
    };
  }

  private async deriveSessionKey(
    privateKey: Uint8Array,
    peerPublicKey: Uint8Array
  ): Promise<Uint8Array> {
    // X25519 ECDH
    const sharedSecret = await crypto.subtle.deriveBits(
      { name: 'X25519', public: await this.importX25519PublicKey(peerPublicKey) },
      await this.importX25519PrivateKey(privateKey),
      256
    );

    // HKDF to derive session key
    const hkdfKey = await crypto.subtle.importKey(
      'raw',
      sharedSecret,
      'HKDF',
      false,
      ['deriveBits']
    );

    const sessionKey = await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        salt: new TextEncoder().encode('clawdstrike-coordination'),
        info: new TextEncoder().encode('session-key'),
        hash: 'SHA-256',
      },
      hkdfKey,
      256
    );

    return new Uint8Array(sessionKey);
  }

  private async encrypt(
    plaintext: Uint8Array,
    nonce: Uint8Array,
    aad: Uint8Array
  ): Promise<Uint8Array> {
    const key = await crypto.subtle.importKey(
      'raw',
      this.sessionKey!,
      { name: 'AES-GCM' },
      false,
      ['encrypt']
    );

    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: aad },
      key,
      plaintext
    );

    return new Uint8Array(ciphertext);
  }

  private async decrypt(
    ciphertext: Uint8Array,
    nonce: Uint8Array
  ): Promise<Uint8Array> {
    const key = await crypto.subtle.importKey(
      'raw',
      this.sessionKey!,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    // Reconstruct AAD from nonce (contains sequence number)
    const aad = nonce; // Simplified - real implementation would include more

    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: aad },
      key,
      ciphertext
    );

    return new Uint8Array(plaintext);
  }

  private validateMessage(message: Message): void {
    // Check timestamp (prevent replay)
    const now = Date.now();
    const maxSkew = 60 * 1000; // 1 minute
    if (Math.abs(now - message.timestamp) > maxSkew) {
      throw new Error('Message timestamp out of range');
    }

    // Check sender
    if (this.peerIdentity && message.from !== this.peerIdentity.id) {
      throw new Error('Message from unexpected sender');
    }

    // Check recipient
    if (message.to !== this.identity.id) {
      throw new Error('Message not addressed to us');
    }
  }

  private async verifyPeerIdentity(summary: AgentIdentitySummary): Promise<void> {
    // Verify certificate fingerprint matches claimed identity
    // Verify certificate chain
    // Verify certificate is not revoked
    // This would integrate with the identity authority
  }

  private getIdentitySummary(): AgentIdentitySummary {
    return {
      id: this.identity.id,
      publicKey: base64.encode(this.identity.publicKey.raw),
      certificateFingerprint: this.computeCertFingerprint(this.identity.certificate),
      metadata: this.identity.metadata,
    };
  }

  private buildAAD(message: Message): Uint8Array {
    // Additional authenticated data: sender, recipient, sequence
    const aadObj = {
      from: message.from,
      to: message.to,
      seq: message.seq,
      type: message.type,
    };
    return new TextEncoder().encode(JSON.stringify(aadObj));
  }

  private generateNonce(): Uint8Array {
    // 12-byte nonce for AES-GCM
    const nonce = new Uint8Array(12);
    // First 4 bytes: sequence number
    const view = new DataView(nonce.buffer);
    view.setUint32(0, this.sequenceNumber, false);
    // Remaining 8 bytes: random
    crypto.getRandomValues(nonce.subarray(4));
    return nonce;
  }

  private generateMessageId(): string {
    return `msg-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
  }

  private generateTaskId(): string {
    return `task-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
  }

  private generateKeyId(): string {
    return `key-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
  }

  /**
   * Generate ephemeral X25519 key pair for key exchange.
   *
   * NOTE: X25519 support in Web Crypto API:
   * - Node.js 18+: Native support via crypto.subtle
   * - Browsers: Limited support; use noble-curves or libsodium-wrappers polyfill
   * - Deno: Supported via crypto.subtle
   *
   * For production, consider using @noble/curves for cross-platform compatibility:
   *   import { x25519 } from '@noble/curves/ed25519';
   *   const privateKey = x25519.utils.randomPrivateKey();
   *   const publicKey = x25519.getPublicKey(privateKey);
   */
  private async generateEphemeralKeyPair(): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }> {
    // Node.js 18+ implementation using crypto.subtle
    const keyPair = await crypto.subtle.generateKey(
      { name: 'X25519' },
      true,
      ['deriveBits']
    );

    const publicKey = await crypto.subtle.exportKey('raw', keyPair.publicKey);
    const privateKey = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);

    return {
      publicKey: new Uint8Array(publicKey),
      privateKey: new Uint8Array(privateKey),
    };
  }

  private async importX25519PublicKey(raw: Uint8Array): Promise<CryptoKey> {
    return crypto.subtle.importKey('raw', raw, { name: 'X25519' }, false, []);
  }

  private async importX25519PrivateKey(pkcs8: Uint8Array): Promise<CryptoKey> {
    return crypto.subtle.importKey('pkcs8', pkcs8, { name: 'X25519' }, false, ['deriveBits']);
  }

  private computeCertFingerprint(cert: Uint8Array): string {
    // SHA-256 fingerprint
    return crypto.subtle.digest('SHA-256', cert)
      .then(hash => Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join(':'));
  }

  private addHandler(type: MessageType, handler: MessageHandler): void {
    if (!this.messageHandlers.has(type)) {
      this.messageHandlers.set(type, []);
    }
    this.messageHandlers.get(type)!.push(handler);
  }

  private waitForOpen(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.ws!.addEventListener('open', () => resolve());
      this.ws!.addEventListener('error', reject);
    });
  }

  private waitForMessage(type: MessageType): Promise<MessageEvent> {
    return new Promise((resolve) => {
      const handler = (event: MessageEvent) => {
        const message = cbor.decode(event.data) as Message;
        if (message.type === type) {
          this.ws!.removeEventListener('message', handler);
          resolve(event);
        }
      };
      this.ws!.addEventListener('message', handler);
    });
  }
}

/**
 * Task request
 */
export interface TaskRequest {
  type: string;
  parameters: Record<string, unknown>;
  priority?: number;
  timeout?: number;
  delegationToken?: DelegationToken;
  requiredCapabilities?: Capability[];
  parentContext?: TaskContext;
  traceId?: string;
}

/**
 * Task result
 */
export interface TaskResult {
  taskId: string;
  success: boolean;
  result?: unknown;
  error?: string;
  evidence?: ExecutionEvidence;
}

/**
 * Task result payload (from handler)
 */
export interface TaskResultPayload {
  success: boolean;
  result?: unknown;
  error?: string;
  evidence?: ExecutionEvidence;
}

/**
 * Channel configuration
 */
export interface ChannelConfig {
  privateKey: string;
  trustedCAs: string[];
  maxMessageSize?: number;
  heartbeatInterval?: number;
  taskTimeout?: number;
}

type MessageHandler = (message: Message) => void | Promise<void>;

class TaskPromise {
  private taskId: string;
  private timeout: number;
  private ackResolve: ((ack: TaskAckMessage) => void) | null = null;
  private resultResolve: ((result: TaskResultMessage) => void) | null = null;

  constructor(taskId: string, timeout: number = 30000) {
    this.taskId = taskId;
    this.timeout = timeout;
  }

  waitForAck(): Promise<TaskAckMessage> {
    return new Promise((resolve, reject) => {
      this.ackResolve = resolve;
      setTimeout(() => reject(new Error('Ack timeout')), this.timeout);
    });
  }

  waitForResult(): Promise<TaskResultMessage> {
    return new Promise((resolve, reject) => {
      this.resultResolve = resolve;
      setTimeout(() => reject(new Error('Result timeout')), this.timeout);
    });
  }

  resolveAck(ack: TaskAckMessage): void {
    this.ackResolve?.(ack);
  }

  resolveResult(result: TaskResultMessage): void {
    this.resultResolve?.(result);
  }
}
```

### Rust Interface

```rust
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

/// Message types
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageType {
    ChannelInit,
    ChannelAccept,
    ChannelClose,
    Task,
    TaskAck,
    TaskResult,
    ResultAck,
    Event,
    Heartbeat,
    HeartbeatAck,
    Error,
}

/// Base message
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message {
    #[serde(rename = "type")]
    pub msg_type: MessageType,
    pub id: String,
    pub seq: u64,
    pub timestamp: i64,
    pub trace_id: Option<String>,
    pub from: AgentId,
    pub to: AgentId,
    pub payload: serde_json::Value,
}

/// Task message payload
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskPayload {
    pub task_id: String,
    pub task_type: String,
    pub parameters: serde_json::Value,
    pub priority: Option<u8>,
    pub timeout_ms: Option<u64>,
    pub delegation_token: Option<String>,
    pub required_capabilities: Option<Vec<Capability>>,
    pub parent_context: Option<TaskContext>,
}

/// Task acknowledgment payload
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskAckPayload {
    pub task_id: String,
    pub accepted: bool,
    pub reason: Option<String>,
    pub estimated_completion_ms: Option<u64>,
}

/// Task result payload
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskResultPayload {
    pub task_id: String,
    pub success: bool,
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
    pub evidence: Option<ExecutionEvidence>,
    pub resource_usage: Option<ResourceUsage>,
}

/// Event payload
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventPayload {
    pub event_type: String,
    pub data: serde_json::Value,
    pub source: AgentId,
    pub event_time: i64,
}

/// Task context
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskContext {
    pub parent_task_id: String,
    pub original_requester: AgentId,
    pub delegation_chain: Vec<String>,
    pub remaining_timeout_ms: Option<u64>,
}

/// Execution evidence
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionEvidence {
    pub start_time: i64,
    pub end_time: i64,
    pub actions: Vec<ExecutionAction>,
    pub signature: String,
}

/// Execution action
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionAction {
    pub action_type: String,
    pub target: String,
    pub result: ActionResult,
    pub timestamp: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActionResult {
    Success,
    Failure,
}

/// Channel configuration
#[derive(Clone, Debug)]
pub struct ChannelConfig {
    pub private_key: Vec<u8>,
    pub certificate: Vec<u8>,
    pub trusted_cas: Vec<Vec<u8>>,
    pub max_message_size: usize,
    pub heartbeat_interval: std::time::Duration,
    pub task_timeout: std::time::Duration,
}

impl Default for ChannelConfig {
    fn default() -> Self {
        Self {
            private_key: vec![],
            certificate: vec![],
            trusted_cas: vec![],
            max_message_size: 16 * 1024 * 1024, // 16 MB
            heartbeat_interval: std::time::Duration::from_secs(30),
            task_timeout: std::time::Duration::from_secs(300),
        }
    }
}

/// Coordination channel
pub struct CoordinationChannel {
    identity: Arc<AgentIdentity>,
    config: ChannelConfig,
    peer_identity: RwLock<Option<AgentIdentitySummary>>,
    session_key: RwLock<Option<Vec<u8>>>,
    sequence: RwLock<u64>,
    pending_tasks: RwLock<HashMap<String, TaskPromise>>,
    message_tx: Option<mpsc::Sender<Message>>,
    message_rx: Option<mpsc::Receiver<Message>>,
}

impl CoordinationChannel {
    pub fn new(identity: Arc<AgentIdentity>, config: ChannelConfig) -> Self {
        Self {
            identity,
            config,
            peer_identity: RwLock::new(None),
            session_key: RwLock::new(None),
            sequence: RwLock::new(0),
            pending_tasks: RwLock::new(HashMap::new()),
            message_tx: None,
            message_rx: None,
        }
    }

    /// Connect to another agent
    pub async fn connect(&mut self, target_url: &str, target_agent_id: &AgentId) -> Result<(), Error> {
        // Establish TLS connection
        let tls_config = self.build_tls_config()?;
        let stream = self.establish_connection(target_url, tls_config).await?;

        // Set up message channels
        let (tx, rx) = mpsc::channel(100);
        self.message_tx = Some(tx);
        self.message_rx = Some(rx);

        // Spawn message handler
        self.spawn_message_handler(stream);

        // Perform handshake
        self.perform_handshake(target_agent_id).await?;

        Ok(())
    }

    /// Accept incoming connection
    pub async fn accept(&mut self, stream: TlsStream) -> Result<(), Error> {
        let (tx, rx) = mpsc::channel(100);
        self.message_tx = Some(tx);
        self.message_rx = Some(rx);

        self.spawn_message_handler(stream);

        // Wait for channel init
        let init = self.receive_message_of_type(MessageType::ChannelInit).await?;
        let init_payload: ChannelInitPayload = serde_json::from_value(init.payload)?;

        // Verify peer identity
        self.verify_peer_identity(&init_payload.identity).await?;

        // Perform key exchange
        let (shared_secret, response_key) = self.perform_key_exchange(&init_payload.key_exchange).await?;

        {
            let mut session_key = self.session_key.write().await;
            *session_key = Some(shared_secret);
        }
        {
            let mut peer = self.peer_identity.write().await;
            *peer = Some(init_payload.identity);
        }

        // Send accept
        self.send_message(Message {
            msg_type: MessageType::ChannelAccept,
            id: self.generate_message_id(),
            seq: self.next_sequence().await,
            timestamp: Utc::now().timestamp_millis(),
            trace_id: None,
            from: self.identity.id.clone(),
            to: init.from,
            payload: serde_json::to_value(ChannelAcceptPayload {
                protocol_version: "1.0.0".to_string(),
                identity: self.get_identity_summary(),
                capabilities: self.identity.capabilities.clone(),
                selected_cipher: "AES-256-GCM".to_string(),
                key_exchange: response_key,
            })?,
        }).await?;

        Ok(())
    }

    /// Send a task
    pub async fn send_task(&self, task: TaskRequest) -> Result<TaskResult, Error> {
        let task_id = self.generate_task_id();

        let message = Message {
            msg_type: MessageType::Task,
            id: self.generate_message_id(),
            seq: self.next_sequence().await,
            timestamp: Utc::now().timestamp_millis(),
            trace_id: task.trace_id,
            from: self.identity.id.clone(),
            to: self.peer_identity.read().await.as_ref().unwrap().id.clone(),
            payload: serde_json::to_value(TaskPayload {
                task_id: task_id.clone(),
                task_type: task.task_type,
                parameters: task.parameters,
                priority: task.priority,
                timeout_ms: task.timeout.map(|t| t.as_millis() as u64),
                delegation_token: task.delegation_token,
                required_capabilities: task.required_capabilities,
                parent_context: task.parent_context,
            })?,
        };

        // Create promise
        let promise = TaskPromise::new(task_id.clone(), task.timeout.unwrap_or(self.config.task_timeout));
        {
            let mut pending = self.pending_tasks.write().await;
            pending.insert(task_id.clone(), promise.clone());
        }

        // Send message
        self.send_message(message).await?;

        // Wait for ack
        let ack = promise.wait_for_ack().await?;
        if !ack.accepted {
            return Err(Error::TaskRejected(ack.reason.unwrap_or_default()));
        }

        // Wait for result
        let result = promise.wait_for_result().await?;

        // Send result ack
        self.send_message(Message {
            msg_type: MessageType::ResultAck,
            id: self.generate_message_id(),
            seq: self.next_sequence().await,
            timestamp: Utc::now().timestamp_millis(),
            trace_id: None,
            from: self.identity.id.clone(),
            to: self.peer_identity.read().await.as_ref().unwrap().id.clone(),
            payload: serde_json::json!({ "task_id": task_id }),
        }).await?;

        // Cleanup
        {
            let mut pending = self.pending_tasks.write().await;
            pending.remove(&task_id);
        }

        Ok(TaskResult {
            task_id,
            success: result.success,
            result: result.result,
            error: result.error,
            evidence: result.evidence,
        })
    }

    /// Register a task handler
    pub fn on_task<F, Fut>(&self, task_type: String, handler: F)
    where
        F: Fn(TaskPayload) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = TaskResultPayload> + Send,
    {
        // Would store handler and call on incoming task messages
    }

    /// Publish an event
    pub async fn publish_event(&self, event_type: &str, data: serde_json::Value) -> Result<(), Error> {
        self.send_message(Message {
            msg_type: MessageType::Event,
            id: self.generate_message_id(),
            seq: self.next_sequence().await,
            timestamp: Utc::now().timestamp_millis(),
            trace_id: None,
            from: self.identity.id.clone(),
            to: self.peer_identity.read().await.as_ref().unwrap().id.clone(),
            payload: serde_json::to_value(EventPayload {
                event_type: event_type.to_string(),
                data,
                source: self.identity.id.clone(),
                event_time: Utc::now().timestamp_millis(),
            })?,
        }).await
    }

    /// Close the channel
    pub async fn close(&self) -> Result<(), Error> {
        self.send_message(Message {
            msg_type: MessageType::ChannelClose,
            id: self.generate_message_id(),
            seq: self.next_sequence().await,
            timestamp: Utc::now().timestamp_millis(),
            trace_id: None,
            from: self.identity.id.clone(),
            to: self.peer_identity.read().await.as_ref().unwrap().id.clone(),
            payload: serde_json::json!({}),
        }).await
    }

    async fn send_message(&self, message: Message) -> Result<(), Error> {
        let session_key = self.session_key.read().await;
        let key = session_key.as_ref().ok_or(Error::NotConnected)?;

        // Serialize
        let plaintext = serde_cbor::to_vec(&message)?;

        // Encrypt
        let nonce = self.generate_nonce().await;
        let aad = self.build_aad(&message);
        let ciphertext = self.encrypt(&plaintext, &nonce, &aad, key)?;

        // Frame
        let mut frame = Vec::with_capacity(4 + 12 + ciphertext.len());
        frame.extend_from_slice(&((12 + ciphertext.len()) as u32).to_be_bytes());
        frame.extend_from_slice(&nonce);
        frame.extend_from_slice(&ciphertext);

        // Send
        if let Some(tx) = &self.message_tx {
            tx.send(message).await.map_err(|_| Error::ChannelClosed)?;
        }

        Ok(())
    }

    async fn receive_message_of_type(&self, msg_type: MessageType) -> Result<Message, Error> {
        // Would read from message_rx and filter by type
        todo!()
    }

    async fn perform_handshake(&mut self, target: &AgentId) -> Result<(), Error> {
        // Generate ephemeral key pair
        let ephemeral = self.generate_ephemeral_key_pair()?;

        // Send init
        self.send_unencrypted(Message {
            msg_type: MessageType::ChannelInit,
            id: self.generate_message_id(),
            seq: self.next_sequence().await,
            timestamp: Utc::now().timestamp_millis(),
            trace_id: None,
            from: self.identity.id.clone(),
            to: target.clone(),
            payload: serde_json::to_value(ChannelInitPayload {
                protocol_version: "1.0.0".to_string(),
                identity: self.get_identity_summary(),
                capabilities: self.identity.capabilities.clone(),
                supported_ciphers: vec!["AES-256-GCM".to_string()],
                key_exchange: KeyExchangeData {
                    public_key: base64::encode(&ephemeral.public_key),
                    key_id: self.generate_key_id(),
                },
            })?,
        }).await?;

        // Wait for accept
        let accept = self.receive_unencrypted().await?;
        let accept_payload: ChannelAcceptPayload = serde_json::from_value(accept.payload)?;

        // Verify peer
        self.verify_peer_identity(&accept_payload.identity).await?;

        // Complete key exchange
        let peer_public = base64::decode(&accept_payload.key_exchange.public_key)?;
        let shared_secret = self.derive_session_key(&ephemeral.private_key, &peer_public)?;

        {
            let mut key = self.session_key.write().await;
            *key = Some(shared_secret);
        }
        {
            let mut peer = self.peer_identity.write().await;
            *peer = Some(accept_payload.identity);
        }

        Ok(())
    }

    async fn perform_key_exchange(&self, peer_key: &KeyExchangeData) -> Result<(Vec<u8>, KeyExchangeData), Error> {
        let ephemeral = self.generate_ephemeral_key_pair()?;
        let peer_public = base64::decode(&peer_key.public_key)?;
        let shared_secret = self.derive_session_key(&ephemeral.private_key, &peer_public)?;

        Ok((
            shared_secret,
            KeyExchangeData {
                public_key: base64::encode(&ephemeral.public_key),
                key_id: self.generate_key_id(),
            },
        ))
    }

    fn derive_session_key(&self, private: &[u8], peer_public: &[u8]) -> Result<Vec<u8>, Error> {
        use x25519_dalek::{PublicKey, StaticSecret};

        let secret = StaticSecret::from(<[u8; 32]>::try_from(private)?);
        let public = PublicKey::from(<[u8; 32]>::try_from(peer_public)?);
        let shared = secret.diffie_hellman(&public);

        // HKDF
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hk = Hkdf::<Sha256>::new(Some(b"clawdstrike-coordination"), shared.as_bytes());
        let mut session_key = [0u8; 32];
        hk.expand(b"session-key", &mut session_key)
            .map_err(|_| Error::KeyDerivationFailed)?;

        Ok(session_key.to_vec())
    }

    fn encrypt(&self, plaintext: &[u8], nonce: &[u8], aad: &[u8], key: &[u8]) -> Result<Vec<u8>, Error> {
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

        let cipher = Aes256Gcm::new_from_slice(key)?;
        let nonce = Nonce::from_slice(nonce);

        cipher.encrypt(nonce, aes_gcm::aead::Payload { msg: plaintext, aad })
            .map_err(|_| Error::EncryptionFailed)
    }

    fn decrypt(&self, ciphertext: &[u8], nonce: &[u8], aad: &[u8], key: &[u8]) -> Result<Vec<u8>, Error> {
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

        let cipher = Aes256Gcm::new_from_slice(key)?;
        let nonce = Nonce::from_slice(nonce);

        cipher.decrypt(nonce, aes_gcm::aead::Payload { msg: ciphertext, aad })
            .map_err(|_| Error::DecryptionFailed)
    }

    async fn verify_peer_identity(&self, summary: &AgentIdentitySummary) -> Result<(), Error> {
        // Verify certificate, etc.
        Ok(())
    }

    fn get_identity_summary(&self) -> AgentIdentitySummary {
        AgentIdentitySummary {
            id: self.identity.id.clone(),
            public_key: base64::encode(&self.identity.public_key.raw),
            certificate_fingerprint: self.compute_cert_fingerprint(&self.identity.certificate),
            name: self.identity.metadata.name.clone(),
            role: self.identity.metadata.role.clone(),
        }
    }

    fn compute_cert_fingerprint(&self, cert: &[u8]) -> String {
        use sha2::{Sha256, Digest};
        let hash = Sha256::digest(cert);
        hash.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":")
    }

    fn build_aad(&self, message: &Message) -> Vec<u8> {
        serde_json::json!({
            "from": message.from,
            "to": message.to,
            "seq": message.seq,
            "type": message.msg_type,
        }).to_string().into_bytes()
    }

    async fn generate_nonce(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        let seq = *self.sequence.read().await;
        nonce[0..4].copy_from_slice(&(seq as u32).to_be_bytes());
        getrandom::getrandom(&mut nonce[4..]).unwrap();
        nonce
    }

    fn generate_ephemeral_key_pair(&self) -> Result<EphemeralKeyPair, Error> {
        use x25519_dalek::{PublicKey, StaticSecret};
        use rand::rngs::OsRng;

        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);

        Ok(EphemeralKeyPair {
            private_key: secret.as_bytes().to_vec(),
            public_key: public.as_bytes().to_vec(),
        })
    }

    fn generate_message_id(&self) -> String {
        format!("msg-{}-{}", Utc::now().timestamp_millis(), uuid::Uuid::new_v4())
    }

    fn generate_task_id(&self) -> String {
        format!("task-{}-{}", Utc::now().timestamp_millis(), uuid::Uuid::new_v4())
    }

    fn generate_key_id(&self) -> String {
        format!("key-{}", uuid::Uuid::new_v4())
    }

    async fn next_sequence(&self) -> u64 {
        let mut seq = self.sequence.write().await;
        let current = *seq;
        *seq += 1;
        current
    }

    fn build_tls_config(&self) -> Result<TlsConfig, Error> {
        todo!()
    }

    async fn establish_connection(&self, url: &str, config: TlsConfig) -> Result<TlsStream, Error> {
        todo!()
    }

    fn spawn_message_handler(&self, stream: TlsStream) {
        // Spawn tokio task to handle incoming messages
    }

    async fn send_unencrypted(&self, message: Message) -> Result<(), Error> {
        todo!()
    }

    async fn receive_unencrypted(&self) -> Result<Message, Error> {
        todo!()
    }
}

/// Channel init payload
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ChannelInitPayload {
    protocol_version: String,
    identity: AgentIdentitySummary,
    capabilities: Vec<Capability>,
    supported_ciphers: Vec<String>,
    key_exchange: KeyExchangeData,
}

/// Channel accept payload
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ChannelAcceptPayload {
    protocol_version: String,
    identity: AgentIdentitySummary,
    capabilities: Vec<Capability>,
    selected_cipher: String,
    key_exchange: KeyExchangeData,
}

/// Agent identity summary
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentIdentitySummary {
    pub id: AgentId,
    pub public_key: String,
    pub certificate_fingerprint: String,
    pub name: String,
    pub role: Option<String>,
}

/// Key exchange data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyExchangeData {
    pub public_key: String,
    pub key_id: String,
}

/// Ephemeral key pair
struct EphemeralKeyPair {
    private_key: Vec<u8>,
    public_key: Vec<u8>,
}

/// Task request
#[derive(Clone, Debug)]
pub struct TaskRequest {
    pub task_type: String,
    pub parameters: serde_json::Value,
    pub priority: Option<u8>,
    pub timeout: Option<std::time::Duration>,
    pub delegation_token: Option<String>,
    pub required_capabilities: Option<Vec<Capability>>,
    pub parent_context: Option<TaskContext>,
    pub trace_id: Option<String>,
}

/// Task result
#[derive(Clone, Debug)]
pub struct TaskResult {
    pub task_id: String,
    pub success: bool,
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
    pub evidence: Option<ExecutionEvidence>,
}

/// Task promise for async completion
#[derive(Clone)]
struct TaskPromise {
    task_id: String,
    timeout: std::time::Duration,
    ack_tx: Option<tokio::sync::oneshot::Sender<TaskAckPayload>>,
    result_tx: Option<tokio::sync::oneshot::Sender<TaskResultPayload>>,
}

impl TaskPromise {
    fn new(task_id: String, timeout: std::time::Duration) -> Self {
        Self {
            task_id,
            timeout,
            ack_tx: None,
            result_tx: None,
        }
    }

    async fn wait_for_ack(&self) -> Result<TaskAckPayload, Error> {
        todo!()
    }

    async fn wait_for_result(&self) -> Result<TaskResultPayload, Error> {
        todo!()
    }
}

// Placeholder types
type TlsConfig = ();
type TlsStream = ();

/// Error types
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Not connected")]
    NotConnected,
    #[error("Channel closed")]
    ChannelClosed,
    #[error("Task rejected: {0}")]
    TaskRejected(String),
    #[error("Key derivation failed")]
    KeyDerivationFailed,
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_cbor::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Key error")]
    KeyError,
}
```

## Cryptographic Primitives

### Key Exchange

**X25519 ECDH**:
- 32-byte public keys
- 32-byte shared secret
- Forward secrecy via ephemeral keys

### Session Key Derivation

```
HKDF-SHA256(
  IKM = X25519_shared_secret,
  salt = "clawdstrike-coordination",
  info = "session-key",
  L = 32
) -> session_key
```

### Message Encryption

**AES-256-GCM**:
- 32-byte key
- 12-byte nonce (4 bytes sequence + 8 bytes random)
- 16-byte authentication tag
- AAD: `{from, to, seq, type}`

### Message Authentication

1. TLS mutual authentication (certificate verification)
2. Channel-level key confirmation
3. Per-message sequence numbers
4. Timestamp validation (60-second window)

## Attack Scenarios and Mitigations

### Attack 1: Replay Attack

**Attack**: Attacker captures and replays valid message

**Mitigation**:
- Sequence numbers per channel
- Nonce uniqueness enforcement
- Timestamp validation

### Attack 2: Key Compromise Forward Secrecy

**Attack**: Session key compromised, decrypt past messages

**Mitigation**:
- Ephemeral key exchange per session
- Regular key rotation (rekeying)
- Past messages indecipherable with new keys

### Attack 3: Message Truncation

**Attack**: Attacker truncates message to change meaning

**Mitigation**:
- Authenticated encryption (GCM tag)
- Length-prefix framing
- Complete message or nothing

### Attack 4: Protocol Downgrade

**Attack**: Force use of weaker cipher

**Mitigation**:
- Signed capability announcement
- Minimum cipher strength enforcement
- Negotiation transcript verification

## Implementation Phases

### Phase 1: Basic Channels
- TLS establishment
- Channel init/accept
- Unencrypted coordination

### Phase 2: End-to-End Encryption
- X25519 key exchange
- AES-256-GCM encryption
- Sequence number tracking

### Phase 3: Task Coordination
- Task/Ack/Result flow
- Timeout handling
- Evidence collection

### Phase 4: Advanced Features
- Channel multiplexing
- Priority queuing
- Rate limiting

## Trust Model and Assumptions

### Trusted
- TLS implementation
- Cryptographic primitives
- Agent identity certificates

### Untrusted
- Network transport
- Intermediate routers
- Other agents (verified via identity)

### Security Invariants
1. **Confidentiality**: Messages encrypted end-to-end
2. **Integrity**: Tampering detected via authentication tags
3. **Authenticity**: Only certified agents can participate
4. **Freshness**: Replay attacks prevented by nonces/timestamps

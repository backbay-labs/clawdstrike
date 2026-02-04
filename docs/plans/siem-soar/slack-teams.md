# Slack and Microsoft Teams Webhook Integrations

## Problem Statement

Engineering and security teams need lightweight, real-time notifications for Clawdstrike security events in their existing collaboration platforms. While PagerDuty/OpsGenie handle incident management, Slack and Teams integrations serve different needs:

1. Awareness notifications for non-critical events
2. Team-specific channels for security context
3. Interactive responses (future: approve/deny actions)
4. Integration with existing DevSecOps workflows
5. Lower friction than full incident management

## Use Cases

| ID | Use Case | Priority |
|----|----------|----------|
| SL-1 | Post security alerts to Slack channel | P0 |
| SL-2 | Rich message formatting with context | P0 |
| SL-3 | Severity-based channel routing | P1 |
| SL-4 | Thread replies for related events | P1 |
| TM-1 | Post alerts to Teams channel | P0 |
| TM-2 | Adaptive card formatting | P0 |
| TM-3 | Actionable messages (acknowledge) | P2 |

## Architecture

### Integration Pattern

```
+-------------------+     +-------------------------+     +------------------+
|                   |     |                         |     |                  |
|   Clawdstrike     |     |   Webhook Exporter      |     |   Slack          |
|   Engine          |---->|                         |---->|   or Teams       |
|                   |     |   +------------------+  |     |                  |
+-------------------+     |   | MessageFormatter |  |     | - Channels       |
                          |   +------------------+  |     | - Threads        |
                          |   +------------------+  |     | - Cards          |
                          |   | ChannelRouter    |  |     | - Actions        |
                          |   +------------------+  |     +------------------+
                          |   +------------------+  |
                          |   | RateLimiter      |  |
                          |   +------------------+  |
                          +-------------------------+
```

### Component Design

```
+-------------------------------------------------------------------------+
|                          WebhookExporter                                 |
+-------------------------------------------------------------------------+
|                                                                          |
|  +---------------------+  +---------------------+  +-------------------+ |
|  |   SlackFormatter    |  |   TeamsFormatter    |  |   GenericWebhook  | |
|  |   - Block Kit       |  |   - Adaptive Cards  |  |   - JSON payload  | |
|  |   - Attachments     |  |   - MessageCard     |  |   - Template      | |
|  |   - Mrkdwn          |  |   - Actions         |  |   - Headers       | |
|  +---------------------+  +---------------------+  +-------------------+ |
|                                                                          |
|  +---------------------+  +---------------------+  +-------------------+ |
|  |   ChannelRouter     |  |   ThreadManager     |  |   RateLimiter     | |
|  |   - Severity map    |  |   - Thread cache    |  |   - Token bucket  | |
|  |   - Guard map       |  |   - TTL cleanup     |  |   - Per-channel   | |
|  |   - Tenant map      |  |   - Reply linking   |  |   - Burst limit   | |
|  +---------------------+  +---------------------+  +-------------------+ |
|                                                                          |
+-------------------------------------------------------------------------+
```

## API Design

### TypeScript Implementation

```typescript
import {
  BaseExporter,
  ExporterConfig,
  SecurityEvent,
  ExportResult,
  SchemaFormat,
} from '../framework';

/**
 * Slack webhook configuration
 */
export interface SlackConfig {
  /** Default webhook URL */
  webhookUrl: string;

  /** Channel routing */
  routing?: {
    /** Channel by severity */
    bySeverity?: Record<string, string>;
    /** Channel by guard */
    byGuard?: Record<string, string>;
    /** Channel by tenant */
    byTenant?: Record<string, string>;
  };

  /** Message formatting */
  formatting?: {
    /** Include detailed context */
    detailed?: boolean;
    /** Show resource path */
    showPath?: boolean;
    /** Show session info */
    showSession?: boolean;
    /** Color by severity */
    colorBySeverity?: boolean;
  };

  /** Threading configuration */
  threading?: {
    /** Enable threading by session */
    enabled?: boolean;
    /** Thread TTL in minutes */
    ttlMinutes?: number;
  };

  /** Bot identity */
  identity?: {
    username?: string;
    iconEmoji?: string;
    iconUrl?: string;
  };

  /** Rate limiting */
  rateLimit?: {
    /** Requests per minute */
    perMinute?: number;
    /** Burst size */
    burst?: number;
  };
}

/**
 * Microsoft Teams webhook configuration
 */
export interface TeamsConfig {
  /** Default webhook URL */
  webhookUrl: string;

  /** Channel routing by severity */
  routing?: {
    bySeverity?: Record<string, string>;
    byGuard?: Record<string, string>;
  };

  /** Card formatting */
  formatting?: {
    /** Use Adaptive Cards (vs MessageCard) */
    useAdaptiveCards?: boolean;
    /** Include facts section */
    showFacts?: boolean;
    /** Include actions */
    showActions?: boolean;
  };

  /** Theme color for cards */
  themeColor?: string;
}

/**
 * Generic webhook configuration
 */
export interface GenericWebhookConfig {
  /** Webhook URL */
  url: string;
  /** HTTP method */
  method?: 'POST' | 'PUT';
  /** Custom headers */
  headers?: Record<string, string>;
  /** Payload template (Handlebars) */
  template?: string;
  /** Authentication */
  auth?: {
    type: 'bearer' | 'basic' | 'header';
    token?: string;
    username?: string;
    password?: string;
    headerName?: string;
    headerValue?: string;
  };
}

/**
 * Combined webhook configuration
 */
export interface WebhookConfig extends ExporterConfig {
  /** Slack configuration */
  slack?: SlackConfig;
  /** Teams configuration */
  teams?: TeamsConfig;
  /** Generic webhooks */
  webhooks?: GenericWebhookConfig[];
  /** Minimum severity to notify */
  minSeverity?: string;
  /** Guards to include */
  includeGuards?: string[];
  /** Guards to exclude */
  excludeGuards?: string[];
}

/**
 * Slack Block Kit message
 */
export interface SlackMessage {
  channel?: string;
  username?: string;
  icon_emoji?: string;
  icon_url?: string;
  thread_ts?: string;
  blocks: SlackBlock[];
  attachments?: SlackAttachment[];
}

export type SlackBlock =
  | SlackHeaderBlock
  | SlackSectionBlock
  | SlackContextBlock
  | SlackDividerBlock
  | SlackActionsBlock;

export interface SlackHeaderBlock {
  type: 'header';
  text: {
    type: 'plain_text';
    text: string;
    emoji?: boolean;
  };
}

export interface SlackSectionBlock {
  type: 'section';
  text?: {
    type: 'mrkdwn' | 'plain_text';
    text: string;
  };
  fields?: Array<{
    type: 'mrkdwn' | 'plain_text';
    text: string;
  }>;
  accessory?: SlackAccessory;
}

export interface SlackContextBlock {
  type: 'context';
  elements: Array<{
    type: 'mrkdwn' | 'plain_text' | 'image';
    text?: string;
    image_url?: string;
    alt_text?: string;
  }>;
}

export interface SlackDividerBlock {
  type: 'divider';
}

export interface SlackActionsBlock {
  type: 'actions';
  elements: SlackActionElement[];
}

export interface SlackAccessory {
  type: 'button' | 'image';
  text?: { type: 'plain_text'; text: string };
  url?: string;
  action_id?: string;
  image_url?: string;
  alt_text?: string;
}

export interface SlackActionElement {
  type: 'button';
  text: { type: 'plain_text'; text: string };
  action_id: string;
  url?: string;
  value?: string;
  style?: 'primary' | 'danger';
}

export interface SlackAttachment {
  color?: string;
  fallback?: string;
  text?: string;
  fields?: Array<{ title: string; value: string; short?: boolean }>;
  footer?: string;
  ts?: number;
}

/**
 * Slack message formatter
 */
export class SlackFormatter {
  private config: Required<SlackConfig['formatting']>;

  private readonly severityColors: Record<string, string> = {
    critical: '#dc3545',
    high: '#fd7e14',
    medium: '#ffc107',
    low: '#17a2b8',
    info: '#6c757d',
  };

  private readonly severityEmojis: Record<string, string> = {
    critical: ':rotating_light:',
    high: ':warning:',
    medium: ':large_orange_diamond:',
    low: ':information_source:',
    info: ':speech_balloon:',
  };

  constructor(config: SlackConfig['formatting'] = {}) {
    this.config = {
      detailed: config.detailed ?? true,
      showPath: config.showPath ?? true,
      showSession: config.showSession ?? true,
      colorBySeverity: config.colorBySeverity ?? true,
    };
  }

  format(event: SecurityEvent): SlackMessage {
    const emoji = this.severityEmojis[event.decision.severity] ?? ':grey_question:';
    const action = event.decision.allowed ? 'ALLOWED' : 'BLOCKED';
    const color = this.severityColors[event.decision.severity] ?? '#6c757d';

    const blocks: SlackBlock[] = [
      {
        type: 'header',
        text: {
          type: 'plain_text',
          text: `${emoji} Security ${action}: ${event.decision.guard}`,
          emoji: true,
        },
      },
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*Reason:* ${event.decision.reason}`,
        },
      },
    ];

    // Add fields
    const fields: Array<{ type: 'mrkdwn'; text: string }> = [
      { type: 'mrkdwn', text: `*Severity:*\n${event.decision.severity.toUpperCase()}` },
      { type: 'mrkdwn', text: `*Guard:*\n${event.decision.guard}` },
      { type: 'mrkdwn', text: `*Event Type:*\n${event.event_type}` },
      { type: 'mrkdwn', text: `*Outcome:*\n${event.outcome}` },
    ];

    blocks.push({
      type: 'section',
      fields,
    });

    // Resource details
    if (this.config.detailed) {
      const resourceFields: Array<{ type: 'mrkdwn'; text: string }> = [
        { type: 'mrkdwn', text: `*Resource Type:*\n${event.resource.type}` },
        { type: 'mrkdwn', text: `*Resource:*\n${event.resource.name}` },
      ];

      if (this.config.showPath && event.resource.path) {
        resourceFields.push({
          type: 'mrkdwn',
          text: `*Path:*\n\`${event.resource.path}\``,
        });
      }

      if (event.resource.host) {
        resourceFields.push({
          type: 'mrkdwn',
          text: `*Host:*\n${event.resource.host}:${event.resource.port ?? ''}`,
        });
      }

      blocks.push({ type: 'divider' });
      blocks.push({
        type: 'section',
        fields: resourceFields,
      });
    }

    // Session context
    if (this.config.showSession) {
      const contextElements: Array<{ type: 'mrkdwn'; text: string }> = [
        { type: 'mrkdwn', text: `Session: \`${event.session.id.slice(0, 8)}...\`` },
      ];

      if (event.session.user_id) {
        contextElements.push({
          type: 'mrkdwn',
          text: `User: ${event.session.user_id}`,
        });
      }

      if (event.session.environment) {
        contextElements.push({
          type: 'mrkdwn',
          text: `Env: ${event.session.environment}`,
        });
      }

      blocks.push({
        type: 'context',
        elements: contextElements,
      });
    }

    // Timestamp context
    blocks.push({
      type: 'context',
      elements: [
        {
          type: 'mrkdwn',
          text: `Event ID: ${event.event_id} | ${new Date(event.timestamp).toISOString()}`,
        },
      ],
    });

    const message: SlackMessage = { blocks };

    if (this.config.colorBySeverity) {
      message.attachments = [
        {
          color,
          fallback: `${action}: ${event.decision.reason}`,
        },
      ];
    }

    return message;
  }
}

/**
 * Microsoft Teams Adaptive Card formatter
 */
export class TeamsFormatter {
  private config: Required<TeamsConfig['formatting']>;
  private themeColor: string;

  private readonly severityColors: Record<string, string> = {
    critical: 'attention',
    high: 'warning',
    medium: 'warning',
    low: 'accent',
    info: 'default',
  };

  constructor(config: TeamsConfig) {
    this.config = {
      useAdaptiveCards: config.formatting?.useAdaptiveCards ?? true,
      showFacts: config.formatting?.showFacts ?? true,
      showActions: config.formatting?.showActions ?? false,
    };
    this.themeColor = config.themeColor ?? '0078D7';
  }

  format(event: SecurityEvent): Record<string, unknown> {
    if (this.config.useAdaptiveCards) {
      return this.formatAdaptiveCard(event);
    }
    return this.formatMessageCard(event);
  }

  private formatAdaptiveCard(event: SecurityEvent): Record<string, unknown> {
    const action = event.decision.allowed ? 'ALLOWED' : 'BLOCKED';
    const color = this.severityColors[event.decision.severity] ?? 'default';

    const body: unknown[] = [
      {
        type: 'TextBlock',
        size: 'Large',
        weight: 'Bolder',
        text: `Security ${action}: ${event.decision.guard}`,
        color,
      },
      {
        type: 'TextBlock',
        text: event.decision.reason,
        wrap: true,
      },
    ];

    if (this.config.showFacts) {
      body.push({
        type: 'FactSet',
        facts: [
          { title: 'Severity', value: event.decision.severity.toUpperCase() },
          { title: 'Guard', value: event.decision.guard },
          { title: 'Event Type', value: event.event_type },
          { title: 'Resource', value: event.resource.name },
          { title: 'Session', value: event.session.id.slice(0, 12) + '...' },
        ],
      });
    }

    const card: Record<string, unknown> = {
      type: 'message',
      attachments: [
        {
          contentType: 'application/vnd.microsoft.card.adaptive',
          contentUrl: null,
          content: {
            $schema: 'http://adaptivecards.io/schemas/adaptive-card.json',
            type: 'AdaptiveCard',
            version: '1.4',
            body,
          },
        },
      ],
    };

    if (this.config.showActions) {
      (card.attachments as any[])[0].content.actions = [
        {
          type: 'Action.OpenUrl',
          title: 'View Details',
          url: `https://clawdstrike.example.com/events/${event.event_id}`,
        },
        {
          type: 'Action.OpenUrl',
          title: 'View Session',
          url: `https://clawdstrike.example.com/sessions/${event.session.id}`,
        },
      ];
    }

    return card;
  }

  private formatMessageCard(event: SecurityEvent): Record<string, unknown> {
    const action = event.decision.allowed ? 'ALLOWED' : 'BLOCKED';

    return {
      '@type': 'MessageCard',
      '@context': 'http://schema.org/extensions',
      themeColor: this.getThemeColor(event.decision.severity),
      summary: `Security ${action}: ${event.decision.guard}`,
      sections: [
        {
          activityTitle: `Security ${action}: ${event.decision.guard}`,
          activitySubtitle: event.decision.reason,
          facts: [
            { name: 'Severity', value: event.decision.severity },
            { name: 'Guard', value: event.decision.guard },
            { name: 'Event Type', value: event.event_type },
            { name: 'Resource', value: event.resource.name },
          ],
          markdown: true,
        },
      ],
    };
  }

  private getThemeColor(severity: string): string {
    const colors: Record<string, string> = {
      critical: 'dc3545',
      high: 'fd7e14',
      medium: 'ffc107',
      low: '17a2b8',
      info: '6c757d',
    };
    return colors[severity] ?? this.themeColor;
  }
}

/**
 * Thread manager for Slack threading
 */
export class ThreadManager {
  private threads: Map<string, { ts: string; expiresAt: number }> = new Map();
  private ttlMs: number;

  constructor(ttlMinutes: number = 60) {
    this.ttlMs = ttlMinutes * 60 * 1000;
  }

  getThreadTs(sessionId: string): string | undefined {
    const thread = this.threads.get(sessionId);
    if (!thread) return undefined;

    if (Date.now() > thread.expiresAt) {
      this.threads.delete(sessionId);
      return undefined;
    }

    return thread.ts;
  }

  setThreadTs(sessionId: string, ts: string): void {
    this.threads.set(sessionId, {
      ts,
      expiresAt: Date.now() + this.ttlMs,
    });
  }

  cleanup(): void {
    const now = Date.now();
    for (const [key, value] of this.threads) {
      if (now > value.expiresAt) {
        this.threads.delete(key);
      }
    }
  }
}

/**
 * Webhook exporter implementation
 */
export class WebhookExporter extends BaseExporter {
  readonly name = 'webhook';
  readonly schema = SchemaFormat.Native;

  private config: Required<WebhookConfig>;
  private slackFormatter?: SlackFormatter;
  private teamsFormatter?: TeamsFormatter;
  private threadManager?: ThreadManager;
  private client: HttpClient;

  private readonly severityOrder = ['info', 'low', 'medium', 'high', 'critical'];

  constructor(config: WebhookConfig) {
    super(config);
    this.config = this.mergeDefaults(config);
    this.client = new HttpClient({ timeout: 30000 });

    if (this.config.slack) {
      this.slackFormatter = new SlackFormatter(this.config.slack.formatting);
      if (this.config.slack.threading?.enabled) {
        this.threadManager = new ThreadManager(
          this.config.slack.threading.ttlMinutes
        );
      }
    }

    if (this.config.teams) {
      this.teamsFormatter = new TeamsFormatter(this.config.teams);
    }
  }

  private mergeDefaults(config: WebhookConfig): Required<WebhookConfig> {
    return {
      slack: config.slack,
      teams: config.teams,
      webhooks: config.webhooks ?? [],
      minSeverity: config.minSeverity ?? 'low',
      includeGuards: config.includeGuards ?? [],
      excludeGuards: config.excludeGuards ?? [],
      ...this.config,
    };
  }

  private shouldNotify(event: SecurityEvent): boolean {
    // Check severity threshold
    const minIndex = this.severityOrder.indexOf(this.config.minSeverity);
    const eventIndex = this.severityOrder.indexOf(event.decision.severity);

    if (eventIndex < minIndex) {
      return false;
    }

    // Check guard filters
    if (this.config.includeGuards.length > 0) {
      if (!this.config.includeGuards.includes(event.decision.guard)) {
        return false;
      }
    }

    if (this.config.excludeGuards.includes(event.decision.guard)) {
      return false;
    }

    return true;
  }

  private getSlackWebhookUrl(event: SecurityEvent): string {
    const routing = this.config.slack?.routing;

    // Check severity routing
    if (routing?.bySeverity?.[event.decision.severity]) {
      return routing.bySeverity[event.decision.severity];
    }

    // Check guard routing
    if (routing?.byGuard?.[event.decision.guard]) {
      return routing.byGuard[event.decision.guard];
    }

    // Check tenant routing
    if (event.session.tenant_id && routing?.byTenant?.[event.session.tenant_id]) {
      return routing.byTenant[event.session.tenant_id];
    }

    return this.config.slack!.webhookUrl;
  }

  private getTeamsWebhookUrl(event: SecurityEvent): string {
    const routing = this.config.teams?.routing;

    if (routing?.bySeverity?.[event.decision.severity]) {
      return routing.bySeverity[event.decision.severity];
    }

    if (routing?.byGuard?.[event.decision.guard]) {
      return routing.byGuard[event.decision.guard];
    }

    return this.config.teams!.webhookUrl;
  }

  async export(events: SecurityEvent[]): Promise<ExportResult> {
    const notifyEvents = events.filter(e => this.shouldNotify(e));

    if (notifyEvents.length === 0) {
      return { exported: 0, failed: 0, errors: [] };
    }

    const errors: ExportError[] = [];
    let exported = 0;

    for (const event of notifyEvents) {
      try {
        await this.sendNotifications(event);
        exported++;
      } catch (error) {
        errors.push({
          eventId: event.event_id,
          error: (error as Error).message,
          retryable: true,
        });
      }
    }

    return { exported, failed: errors.length, errors };
  }

  private async sendNotifications(event: SecurityEvent): Promise<void> {
    const promises: Promise<void>[] = [];

    // Send to Slack
    if (this.config.slack && this.slackFormatter) {
      promises.push(this.sendToSlack(event));
    }

    // Send to Teams
    if (this.config.teams && this.teamsFormatter) {
      promises.push(this.sendToTeams(event));
    }

    // Send to generic webhooks
    for (const webhook of this.config.webhooks) {
      promises.push(this.sendToWebhook(event, webhook));
    }

    await Promise.all(promises);
  }

  private async sendToSlack(event: SecurityEvent): Promise<void> {
    const message = this.slackFormatter!.format(event);
    const url = this.getSlackWebhookUrl(event);

    // Add identity
    if (this.config.slack!.identity) {
      message.username = this.config.slack!.identity.username;
      message.icon_emoji = this.config.slack!.identity.iconEmoji;
      message.icon_url = this.config.slack!.identity.iconUrl;
    }

    // Check for existing thread
    if (this.threadManager) {
      const threadTs = this.threadManager.getThreadTs(event.session.id);
      if (threadTs) {
        message.thread_ts = threadTs;
      }
    }

    const response = await this.client.post(url, message);

    if (response.status !== 200) {
      throw new Error(`Slack webhook error: ${response.status}`);
    }

    // Store thread_ts for future replies
    if (this.threadManager && !message.thread_ts) {
      const body = await response.json();
      if (body.ts) {
        this.threadManager.setThreadTs(event.session.id, body.ts);
      }
    }
  }

  private async sendToTeams(event: SecurityEvent): Promise<void> {
    const message = this.teamsFormatter!.format(event);
    const url = this.getTeamsWebhookUrl(event);

    const response = await this.client.post(url, message);

    if (response.status !== 200) {
      throw new Error(`Teams webhook error: ${response.status}`);
    }
  }

  private async sendToWebhook(
    event: SecurityEvent,
    config: GenericWebhookConfig
  ): Promise<void> {
    let payload: unknown;

    if (config.template) {
      // Use Handlebars template
      const template = Handlebars.compile(config.template);
      payload = JSON.parse(template(event));
    } else {
      payload = event;
    }

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...config.headers,
    };

    // Add authentication
    if (config.auth) {
      switch (config.auth.type) {
        case 'bearer':
          headers['Authorization'] = `Bearer ${config.auth.token}`;
          break;
        case 'basic':
          const basic = Buffer.from(
            `${config.auth.username}:${config.auth.password}`
          ).toString('base64');
          headers['Authorization'] = `Basic ${basic}`;
          break;
        case 'header':
          headers[config.auth.headerName!] = config.auth.headerValue!;
          break;
      }
    }

    const response = await this.client.request({
      method: config.method ?? 'POST',
      url: config.url,
      headers,
      body: payload,
    });

    if (response.status >= 400) {
      throw new Error(`Webhook error: ${response.status}`);
    }
  }

  async healthCheck(): Promise<void> {
    // No standard health check for webhooks
  }

  async shutdown(): Promise<void> {
    this.threadManager?.cleanup();
  }
}
```

### Rust Implementation

```rust
use async_trait::async_trait;
use reqwest::{Client, header};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info};

/// Slack configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackConfig {
    pub webhook_url: String,
    #[serde(default)]
    pub routing: SlackRouting,
    #[serde(default)]
    pub formatting: SlackFormatting,
    #[serde(default)]
    pub threading: ThreadingConfig,
    #[serde(default)]
    pub identity: SlackIdentity,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SlackRouting {
    pub by_severity: HashMap<String, String>,
    pub by_guard: HashMap<String, String>,
    pub by_tenant: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackFormatting {
    #[serde(default = "default_true")]
    pub detailed: bool,
    #[serde(default = "default_true")]
    pub show_path: bool,
    #[serde(default = "default_true")]
    pub color_by_severity: bool,
}

impl Default for SlackFormatting {
    fn default() -> Self {
        Self {
            detailed: true,
            show_path: true,
            color_by_severity: true,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ThreadingConfig {
    pub enabled: bool,
    #[serde(default = "default_ttl")]
    pub ttl_minutes: u64,
}

fn default_ttl() -> u64 { 60 }

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SlackIdentity {
    pub username: Option<String>,
    pub icon_emoji: Option<String>,
    pub icon_url: Option<String>,
}

/// Teams configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamsConfig {
    pub webhook_url: String,
    #[serde(default)]
    pub routing: TeamsRouting,
    #[serde(default)]
    pub formatting: TeamsFormatting,
    #[serde(default = "default_theme")]
    pub theme_color: String,
}

fn default_theme() -> String { "0078D7".to_string() }
fn default_true() -> bool { true }

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TeamsRouting {
    pub by_severity: HashMap<String, String>,
    pub by_guard: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamsFormatting {
    #[serde(default = "default_true")]
    pub use_adaptive_cards: bool,
    #[serde(default = "default_true")]
    pub show_facts: bool,
    #[serde(default)]
    pub show_actions: bool,
}

impl Default for TeamsFormatting {
    fn default() -> Self {
        Self {
            use_adaptive_cards: true,
            show_facts: true,
            show_actions: false,
        }
    }
}

/// Webhook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub slack: Option<SlackConfig>,
    pub teams: Option<TeamsConfig>,
    #[serde(default = "default_min_severity")]
    pub min_severity: String,
    #[serde(default)]
    pub include_guards: Vec<String>,
    #[serde(default)]
    pub exclude_guards: Vec<String>,
}

fn default_min_severity() -> String { "low".to_string() }

/// Thread manager for Slack
struct ThreadManager {
    threads: Arc<RwLock<HashMap<String, (String, chrono::DateTime<chrono::Utc>)>>>,
    ttl: chrono::Duration,
}

impl ThreadManager {
    fn new(ttl_minutes: u64) -> Self {
        Self {
            threads: Arc::new(RwLock::new(HashMap::new())),
            ttl: chrono::Duration::minutes(ttl_minutes as i64),
        }
    }

    async fn get_thread_ts(&self, session_id: &str) -> Option<String> {
        let threads = self.threads.read().await;
        threads.get(session_id).and_then(|(ts, expires_at)| {
            if chrono::Utc::now() < *expires_at {
                Some(ts.clone())
            } else {
                None
            }
        })
    }

    async fn set_thread_ts(&self, session_id: &str, ts: &str) {
        let mut threads = self.threads.write().await;
        threads.insert(
            session_id.to_string(),
            (ts.to_string(), chrono::Utc::now() + self.ttl),
        );
    }
}

/// Slack message formatter
struct SlackFormatter {
    config: SlackFormatting,
}

impl SlackFormatter {
    fn new(config: SlackFormatting) -> Self {
        Self { config }
    }

    fn get_severity_color(&self, severity: &Severity) -> &'static str {
        match severity {
            Severity::Critical => "#dc3545",
            Severity::High => "#fd7e14",
            Severity::Medium => "#ffc107",
            Severity::Low => "#17a2b8",
            Severity::Info => "#6c757d",
        }
    }

    fn get_severity_emoji(&self, severity: &Severity) -> &'static str {
        match severity {
            Severity::Critical => ":rotating_light:",
            Severity::High => ":warning:",
            Severity::Medium => ":large_orange_diamond:",
            Severity::Low => ":information_source:",
            Severity::Info => ":speech_balloon:",
        }
    }

    fn format(&self, event: &SecurityEvent) -> serde_json::Value {
        let emoji = self.get_severity_emoji(&event.decision.severity);
        let action = if event.decision.allowed { "ALLOWED" } else { "BLOCKED" };
        let color = self.get_severity_color(&event.decision.severity);

        let mut blocks = vec![
            json!({
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": format!("{} Security {}: {}", emoji, action, event.decision.guard),
                    "emoji": true
                }
            }),
            json!({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": format!("*Reason:* {}", event.decision.reason)
                }
            }),
            json!({
                "type": "section",
                "fields": [
                    { "type": "mrkdwn", "text": format!("*Severity:*\n{:?}", event.decision.severity) },
                    { "type": "mrkdwn", "text": format!("*Guard:*\n{}", event.decision.guard) },
                    { "type": "mrkdwn", "text": format!("*Event Type:*\n{:?}", event.event_type) },
                    { "type": "mrkdwn", "text": format!("*Outcome:*\n{}", event.outcome) }
                ]
            }),
        ];

        if self.config.detailed {
            blocks.push(json!({ "type": "divider" }));

            let mut resource_fields = vec![
                json!({ "type": "mrkdwn", "text": format!("*Resource Type:*\n{}", event.resource.resource_type) }),
                json!({ "type": "mrkdwn", "text": format!("*Resource:*\n{}", event.resource.name) }),
            ];

            if self.config.show_path {
                if let Some(path) = &event.resource.path {
                    resource_fields.push(json!({
                        "type": "mrkdwn",
                        "text": format!("*Path:*\n`{}`", path)
                    }));
                }
            }

            blocks.push(json!({
                "type": "section",
                "fields": resource_fields
            }));
        }

        // Context footer
        blocks.push(json!({
            "type": "context",
            "elements": [{
                "type": "mrkdwn",
                "text": format!(
                    "Event ID: {} | {}",
                    event.event_id,
                    event.timestamp.to_rfc3339()
                )
            }]
        }));

        let mut message = json!({ "blocks": blocks });

        if self.config.color_by_severity {
            message["attachments"] = json!([{
                "color": color,
                "fallback": format!("{}: {}", action, event.decision.reason)
            }]);
        }

        message
    }
}

/// Teams Adaptive Card formatter
struct TeamsFormatter {
    config: TeamsFormatting,
    theme_color: String,
}

impl TeamsFormatter {
    fn new(config: &TeamsConfig) -> Self {
        Self {
            config: config.formatting.clone(),
            theme_color: config.theme_color.clone(),
        }
    }

    fn get_severity_color(&self, severity: &Severity) -> &'static str {
        match severity {
            Severity::Critical => "attention",
            Severity::High | Severity::Medium => "warning",
            Severity::Low => "accent",
            Severity::Info => "default",
        }
    }

    fn format(&self, event: &SecurityEvent) -> serde_json::Value {
        let action = if event.decision.allowed { "ALLOWED" } else { "BLOCKED" };
        let color = self.get_severity_color(&event.decision.severity);

        let mut body = vec![
            json!({
                "type": "TextBlock",
                "size": "Large",
                "weight": "Bolder",
                "text": format!("Security {}: {}", action, event.decision.guard),
                "color": color
            }),
            json!({
                "type": "TextBlock",
                "text": event.decision.reason,
                "wrap": true
            }),
        ];

        if self.config.show_facts {
            body.push(json!({
                "type": "FactSet",
                "facts": [
                    { "title": "Severity", "value": format!("{:?}", event.decision.severity) },
                    { "title": "Guard", "value": event.decision.guard },
                    { "title": "Event Type", "value": format!("{:?}", event.event_type) },
                    { "title": "Resource", "value": event.resource.name },
                    { "title": "Session", "value": format!("{}...", &event.session.id[..12.min(event.session.id.len())]) }
                ]
            }));
        }

        let mut card = json!({
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": "1.4",
            "body": body
        });

        if self.config.show_actions {
            card["actions"] = json!([
                {
                    "type": "Action.OpenUrl",
                    "title": "View Details",
                    "url": format!("https://clawdstrike.example.com/events/{}", event.event_id)
                }
            ]);
        }

        json!({
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": null,
                "content": card
            }]
        })
    }
}

/// Webhook exporter
pub struct WebhookExporter {
    config: WebhookConfig,
    client: Client,
    slack_formatter: Option<SlackFormatter>,
    teams_formatter: Option<TeamsFormatter>,
    thread_manager: Option<ThreadManager>,
}

impl WebhookExporter {
    pub fn new(config: WebhookConfig) -> Result<Self, ExporterError> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let slack_formatter = config.slack.as_ref()
            .map(|c| SlackFormatter::new(c.formatting.clone()));

        let teams_formatter = config.teams.as_ref()
            .map(|c| TeamsFormatter::new(c));

        let thread_manager = config.slack.as_ref()
            .filter(|c| c.threading.enabled)
            .map(|c| ThreadManager::new(c.threading.ttl_minutes));

        Ok(Self {
            config,
            client,
            slack_formatter,
            teams_formatter,
            thread_manager,
        })
    }

    fn should_notify(&self, event: &SecurityEvent) -> bool {
        let severity_order = ["info", "low", "medium", "high", "critical"];

        let min_idx = severity_order.iter()
            .position(|s| *s == self.config.min_severity)
            .unwrap_or(0);

        let event_severity = format!("{:?}", event.decision.severity).to_lowercase();
        let event_idx = severity_order.iter()
            .position(|s| *s == event_severity)
            .unwrap_or(0);

        if event_idx < min_idx {
            return false;
        }

        if !self.config.include_guards.is_empty()
            && !self.config.include_guards.contains(&event.decision.guard)
        {
            return false;
        }

        if self.config.exclude_guards.contains(&event.decision.guard) {
            return false;
        }

        true
    }

    fn get_slack_url(&self, event: &SecurityEvent) -> &str {
        let config = self.config.slack.as_ref().unwrap();
        let routing = &config.routing;
        let severity = format!("{:?}", event.decision.severity).to_lowercase();

        if let Some(url) = routing.by_severity.get(&severity) {
            return url;
        }

        if let Some(url) = routing.by_guard.get(&event.decision.guard) {
            return url;
        }

        if let Some(tenant) = &event.session.tenant_id {
            if let Some(url) = routing.by_tenant.get(tenant) {
                return url;
            }
        }

        &config.webhook_url
    }

    async fn send_to_slack(&self, event: &SecurityEvent) -> Result<(), ExporterError> {
        let config = self.config.slack.as_ref().unwrap();
        let mut message = self.slack_formatter.as_ref().unwrap().format(event);
        let url = self.get_slack_url(event);

        // Add identity
        if let Some(username) = &config.identity.username {
            message["username"] = json!(username);
        }
        if let Some(emoji) = &config.identity.icon_emoji {
            message["icon_emoji"] = json!(emoji);
        }

        // Check for thread
        if let Some(tm) = &self.thread_manager {
            if let Some(thread_ts) = tm.get_thread_ts(&event.session.id).await {
                message["thread_ts"] = json!(thread_ts);
            }
        }

        let response = self.client
            .post(url)
            .json(&message)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(ExporterError::Http {
                status: response.status().as_u16(),
                body: response.text().await.unwrap_or_default(),
            });
        }

        Ok(())
    }

    async fn send_to_teams(&self, event: &SecurityEvent) -> Result<(), ExporterError> {
        let config = self.config.teams.as_ref().unwrap();
        let message = self.teams_formatter.as_ref().unwrap().format(event);

        let severity = format!("{:?}", event.decision.severity).to_lowercase();
        let url = config.routing.by_severity
            .get(&severity)
            .or_else(|| config.routing.by_guard.get(&event.decision.guard))
            .unwrap_or(&config.webhook_url);

        let response = self.client
            .post(url)
            .json(&message)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(ExporterError::Http {
                status: response.status().as_u16(),
                body: response.text().await.unwrap_or_default(),
            });
        }

        Ok(())
    }
}

#[async_trait]
impl Exporter for WebhookExporter {
    fn name(&self) -> &str {
        "webhook"
    }

    fn schema(&self) -> SchemaFormat {
        SchemaFormat::Native
    }

    async fn export(&self, events: Vec<SecurityEvent>) -> Result<ExportResult, ExportError> {
        let notify_events: Vec<&SecurityEvent> = events
            .iter()
            .filter(|e| self.should_notify(e))
            .collect();

        if notify_events.is_empty() {
            return Ok(ExportResult {
                exported: 0,
                failed: 0,
                errors: vec![],
            });
        }

        let mut exported = 0;
        let mut errors = vec![];

        for event in notify_events {
            let mut event_errors = vec![];

            if self.config.slack.is_some() {
                if let Err(e) = self.send_to_slack(event).await {
                    event_errors.push(format!("Slack: {}", e));
                }
            }

            if self.config.teams.is_some() {
                if let Err(e) = self.send_to_teams(event).await {
                    event_errors.push(format!("Teams: {}", e));
                }
            }

            if event_errors.is_empty() {
                exported += 1;
            } else {
                errors.push(ExportError {
                    event_id: event.event_id.to_string(),
                    error: event_errors.join("; "),
                    retryable: true,
                });
            }
        }

        info!("Sent {} webhook notifications ({} failed)", exported, errors.len());

        Ok(ExportResult {
            exported,
            failed: errors.len(),
            errors,
        })
    }

    async fn health_check(&self) -> Result<(), String> {
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), String> {
        Ok(())
    }
}
```

## Configuration Examples

### Slack Only

```yaml
exporters:
  webhook:
    enabled: true
    min_severity: medium

    slack:
      webhook_url: ${SLACK_WEBHOOK_URL}
      routing:
        by_severity:
          critical: ${SLACK_CRITICAL_WEBHOOK}
          high: ${SLACK_HIGH_WEBHOOK}
        by_guard:
          secret_leak: ${SLACK_DLP_WEBHOOK}
      formatting:
        detailed: true
        show_path: true
        color_by_severity: true
      threading:
        enabled: true
        ttl_minutes: 120
      identity:
        username: Clawdstrike
        icon_emoji: ":shield:"
```

### Teams Only

```yaml
exporters:
  webhook:
    enabled: true
    min_severity: high

    teams:
      webhook_url: ${TEAMS_WEBHOOK_URL}
      routing:
        by_severity:
          critical: ${TEAMS_CRITICAL_WEBHOOK}
      formatting:
        use_adaptive_cards: true
        show_facts: true
        show_actions: true
      theme_color: "0078D7"
```

### Both Platforms

```yaml
exporters:
  webhook:
    enabled: true
    min_severity: medium
    exclude_guards:
      - prompt_injection

    slack:
      webhook_url: ${SLACK_WEBHOOK_URL}
      routing:
        by_severity:
          critical: ${SLACK_CRITICAL_CHANNEL}
      formatting:
        detailed: true
      identity:
        username: Clawdstrike Bot
        icon_emoji: ":robot_face:"

    teams:
      webhook_url: ${TEAMS_WEBHOOK_URL}
      formatting:
        use_adaptive_cards: true
```

## Implementation Phases

### Phase 1: Slack Integration (Week 9)

- [ ] Implement SlackFormatter with Block Kit
- [ ] Channel routing by severity/guard/tenant
- [ ] Thread management for session grouping
- [ ] Unit tests with mock webhooks

### Phase 2: Teams Integration (Week 10)

- [ ] Implement TeamsFormatter with Adaptive Cards
- [ ] MessageCard fallback support
- [ ] Routing configuration
- [ ] Integration tests

### Phase 3: Generic Webhooks (Week 10)

- [ ] Template-based payload formatting
- [ ] Authentication options
- [ ] Custom headers support
- [ ] Documentation and examples

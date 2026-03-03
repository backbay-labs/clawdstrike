/**
 * Base error class for all hunt-related errors.
 */
export class HuntError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    Object.setPrototypeOf(this, new.target.prototype);
    this.name = 'HuntError';
    this.code = code;
  }
}

export class QueryError extends HuntError {
  constructor(message: string) {
    super('QUERY_ERROR', message);
    this.name = 'QueryError';
  }
}

export class ParseError extends HuntError {
  constructor(message: string) {
    super('PARSE_ERROR', message);
    this.name = 'ParseError';
  }
}

export class IoError extends HuntError {
  constructor(message: string) {
    super('IO_ERROR', message);
    this.name = 'IoError';
  }
}

export class CorrelationError extends HuntError {
  constructor(message: string) {
    super('CORRELATION_ERROR', message);
    this.name = 'CorrelationError';
  }
}

export class IocError extends HuntError {
  constructor(message: string) {
    super('IOC_ERROR', message);
    this.name = 'IocError';
  }
}

export class WatchError extends HuntError {
  constructor(message: string) {
    super('WATCH_ERROR', message);
    this.name = 'WatchError';
  }
}

export class ReportError extends HuntError {
  constructor(message: string) {
    super('REPORT_ERROR', message);
    this.name = 'ReportError';
  }
}

export class HuntAlertError extends HuntError {
  constructor(message: string) {
    super('ALERT_DENIED', message);
    this.name = 'HuntAlertError';
  }
}

export class PlaybookError extends HuntError {
  constructor(message: string) {
    super('PLAYBOOK_ERROR', message);
    this.name = 'PlaybookError';
  }
}

export class ExportError extends HuntError {
  constructor(message: string) {
    super('EXPORT_ERROR', message);
    this.name = 'ExportError';
  }
}

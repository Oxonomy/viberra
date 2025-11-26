import process from 'node:process';
import fs from 'node:fs';
import path from 'node:path';
import { createLogger, format, transports } from 'winston';

/**
 * Logs only to file, overwrites on start.
 * VIBE_LOG_FILE — path (default: ./viberra-agent.log)
 * VIBE_LOG_LEVEL — level (info|debug|warn|error)
 */
export const LOG_FILE = process.env.VIBE_LOG_FILE || path.join(process.cwd(), 'viberra-agent.log');
fs.mkdirSync(path.dirname(LOG_FILE), { recursive: true });

export const logger = createLogger({
  level: process.env.VIBE_LOG_LEVEL || 'info',
  format: format.combine(
      format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
      format.errors({ stack: true }),
      format.splat(),
      format.printf(({ timestamp, level, message, stack, ...meta }) => {
        const extra = Object.keys(meta).length ? ` ${JSON.stringify(meta)}` : '';
        return `${timestamp} ${level.toUpperCase()} ${stack ? `${message}\n${stack}` : message}${extra}`;
      }),
  ),
  transports: [ new transports.File({ filename: LOG_FILE, options: { flags: 'w' } }) ],
  exitOnError: false,
});

export const log    = (msg, ...rest) => { try { logger.info(msg, ...rest); } catch {} };
export const logW   = (msg, ...rest) => { try { logger.warn(msg, ...rest); } catch {} };
export const logE   = (msg, ...rest) => { try { logger.error(msg, ...rest); } catch {} };

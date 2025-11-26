import process from 'node:process';
import { VERSION } from './version.mjs';

const GREEN = '\x1b[32m';
const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';

const LOGO = `
██╗   ██╗██╗██████╗ ███████╗██████╗ ██████╗  █████╗
██║   ██║██║██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗
██║   ██║██║██████╔╝█████╗  ██████╔╝██████╔╝███████║
╚██╗ ██╔╝██║██╔══██╗██╔══╝  ██╔══██╗██╔══██╗██╔══██║
 ╚████╔╝ ██║██████╔╝███████╗██║  ██║██║  ██║██║  ██║
  ╚═══╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
`;

/**
 * Prints viberra logo with version and description to stdout
 * Uses color only if stdout is a TTY
 */
export function printLogo() {
  const isTTY = process.stdout.isTTY;

  if (isTTY) {
    process.stdout.write(`${GREEN}${LOGO}${RESET}\n`);
    process.stdout.write(`  ${BOLD}v${VERSION}${RESET} · Secure Remote Terminal\n\n`);
  } else {
    process.stdout.write(`${LOGO}\n`);
    process.stdout.write(`  v${VERSION} · Secure Remote Terminal\n\n`);
  }
}

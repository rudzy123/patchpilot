import { parentPort } from 'node:worker_threads';

import { handleParserWorkerMessage } from './parse-document.js';
import type { ParserThreadMessage } from './parser-thread.js';
import { parserFailure } from './normalize-cyclonedx.js';

if (parentPort === null) {
  throw new Error('CycloneDX parser worker must run as a worker thread.');
}

const port = parentPort;

port.on('message', (message: unknown) => {
  let result: ParserThreadMessage;
  try {
    result = handleParserWorkerMessage(message);
  } catch {
    result = parserFailure('parser_crash');
  }
  port.postMessage(result);
});

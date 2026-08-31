import { parentPort } from 'node:worker_threads';

/**
 * Test-only worker that ignores the payload and busy-loops until the host
 * calls worker.terminate(). Not part of the public parser API.
 */
if (parentPort === null) {
  throw new Error('Hang worker must run as a worker thread.');
}

parentPort.on('message', () => {
  for (let n = 0; n >= 0; n ^= 1) {
    // Busy-loop until the host calls worker.terminate().
  }
});

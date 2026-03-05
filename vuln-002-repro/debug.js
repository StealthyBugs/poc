const path = require('path');

// Simulate what parseUrl does with various payloads
const payloads = [
  '....//....//....//....//etc/passwd',
  '../../../etc/passwd',
  '..%2F..%2F..%2Fetc/passwd',
  '..\\..\\..\\etc/passwd',
  '%2e%2e/%2e%2e/%2e%2e/etc/passwd',
];

const route = '/test-bucket/';
const localDir = '/tmp/fake-bucket';

for (const payload of payloads) {
  console.log('\n--- Payload:', payload, '---');

  const url = '/test-bucket/' + payload;
  const normalized = path.normalize(decodeURIComponent(url));
  console.log('1. normalized URL:', normalized);

  const temp = normalized.split(route);
  console.log('2. split:', JSON.stringify(temp));

  let paramPath = '';
  if (temp[1] !== undefined) {
    paramPath = path.normalize(path.join(paramPath, temp[1].split('?')[0]));
  }
  console.log('3. params.path:', paramPath);

  if (paramPath[0] === '/' || paramPath[0] === '.') {
    paramPath = paramPath.substring(1);
  }
  console.log('4. after strip:', paramPath);

  const filePath = path.normalize(path.join(localDir, paramPath));
  console.log('5. final path:', filePath);
  console.log('6. ESCAPED:', !filePath.startsWith(path.resolve(localDir)));
}

// Also test with prefix parameter
console.log('\n\n=== PREFIX PARAMETER TESTS ===');
const prefixPayloads = [
  '../../../etc/passwd',
  '....//....//....//etc',
  '../../..',
];

for (const prefix of prefixPayloads) {
  console.log('\n--- prefix:', prefix, '---');

  let paramPath = prefix + '/';
  console.log('1. after prefix concat:', paramPath);

  // Simulate temp[1] being empty string (bucket root request)
  const joined = path.normalize(path.join(paramPath, ''));
  console.log('2. after normalize+join:', joined);

  paramPath = joined;
  if (paramPath[0] === '/' || paramPath[0] === '.') {
    paramPath = paramPath.substring(1);
  }
  console.log('3. after strip:', paramPath);

  const filePath = path.normalize(path.join(localDir, paramPath));
  console.log('4. final path:', filePath);
  console.log('5. ESCAPED:', !filePath.startsWith(path.resolve(localDir)));
}

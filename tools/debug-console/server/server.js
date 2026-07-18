const http = require('http');
const fs = require('fs');
const path = require('path');
const {execFile} = require('child_process');

const host = process.env.IPAD_DEBUG_CONSOLE_HOST || '127.0.0.1';
const port = Number.parseInt(process.env.IPAD_DEBUG_CONSOLE_PORT || '8765', 10);
const ipadctl = process.env.IPADCTL_BIN || 'ipadctl';
const supportDir = process.env.IPAD_SUPPORT_DIR || '/tmp/ipad-support';
const staticDir = path.resolve(__dirname, '..', 'static');
const sampleStatusPath = path.resolve(__dirname, 'sample-status.json');

if (host !== '127.0.0.1' && host !== 'localhost') {
  console.error(`Refusing to bind non-local host by default: ${host}`);
  process.exit(2);
}

function buildGlobalArgs() {
  const args = ['--json'];
  if (process.env.IPAD_CONFIG) {
    args.push('--config', process.env.IPAD_CONFIG);
  }
  if (process.env.IPAD_SOCKET) {
    args.push('--socket', process.env.IPAD_SOCKET);
  }
  return args;
}

function runIpadctl(args) {
  return new Promise((resolve) => {
    execFile(ipadctl, args, {timeout: 10000, maxBuffer: 1024 * 512}, (error, stdout, stderr) => {
      const body = stdout || stderr || '';
      resolve({
        ok: !error,
        code: error && typeof error.code === 'number' ? error.code : 0,
        body
      });
    });
  });
}

function readSampleStatus() {
  return JSON.parse(fs.readFileSync(sampleStatusPath, 'utf8'));
}

function parseJsonOrSample(result) {
  try {
    return JSON.parse(result.body);
  } catch (error) {
    const sample = readSampleStatus();
    sample.summary = result.body ? `ipadctl returned non-JSON output: ${result.body.slice(0, 160)}` : 'ipadctl is not available; showing sample diagnostics';
    sample.next_action = 'Run: ipadctl --json doctor';
    return sample;
  }
}

function sendJson(response, statusCode, payload) {
  const body = JSON.stringify(payload);
  response.writeHead(statusCode, {
    'content-type': 'application/json',
    'cache-control': 'no-store',
    'content-length': Buffer.byteLength(body)
  });
  response.end(body);
}

function sendText(response, statusCode, text) {
  response.writeHead(statusCode, {
    'content-type': 'text/plain; charset=utf-8',
    'content-length': Buffer.byteLength(text)
  });
  response.end(text);
}

function contentTypeFor(filePath) {
  if (filePath.endsWith('.html')) return 'text/html; charset=utf-8';
  if (filePath.endsWith('.css')) return 'text/css; charset=utf-8';
  if (filePath.endsWith('.js')) return 'application/javascript; charset=utf-8';
  if (filePath.endsWith('.json')) return 'application/json; charset=utf-8';
  return 'application/octet-stream';
}

function serveStatic(requestPath, response) {
  const normalized = requestPath === '/' ? '/index.html' : requestPath;
  const filePath = path.resolve(staticDir, `.${normalized}`);

  if (!filePath.startsWith(staticDir)) {
    sendText(response, 403, 'forbidden');
    return;
  }
  fs.readFile(filePath, (error, data) => {
    if (error) {
      sendText(response, 404, 'not found');
      return;
    }
    response.writeHead(200, {
      'content-type': contentTypeFor(filePath),
      'cache-control': 'no-store',
      'content-length': data.length
    });
    response.end(data);
  });
}

async function handleApi(request, response, url) {
  if (request.method === 'GET' && url.pathname === '/api/status') {
    const result = await runIpadctl([...buildGlobalArgs(), 'doctor']);
    sendJson(response, 200, parseJsonOrSample(result));
    return;
  }

  if (request.method === 'POST' && url.pathname === '/api/support-bundle') {
    const result = await runIpadctl([...buildGlobalArgs(), 'support', 'bundle', '--output', supportDir]);
    sendJson(response, result.ok ? 200 : 500, parseJsonOrSample(result));
    return;
  }

  sendJson(response, 404, {ok: false, error: 'unknown api route'});
}

const server = http.createServer((request, response) => {
  const url = new URL(request.url, `http://${host}:${port}`);

  if (url.pathname.startsWith('/api/')) {
    handleApi(request, response, url).catch((error) => {
      sendJson(response, 500, {ok: false, error: error.message});
    });
    return;
  }

  serveStatic(url.pathname, response);
});

server.listen(port, host, () => {
  console.log(`IPAd Manager Debug Console listening on http://${host}:${port}`);
  console.log(`Using ipadctl binary: ${ipadctl}`);
});

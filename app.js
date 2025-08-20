{
  "name": "Mobile-friendly Auto Pentest (HTTP checks + Slack)",
  "nodes": [
    {
      "parameters": { "triggerTimes": { "item": [ { "minute": "*/5" } ] } },
      "name": "Cron Every 5m",
      "type": "n8n-nodes-base.cron",
      "typeVersion": 1,
      "position": [250, 300]
    },
    {
      "parameters": {
        "values": {
          "string": [
            { "name": "target", "value": "http://localhost:8000" },
            { "name": "target", "value": "http://127.0.0.1:8000" }
          ]
        }
      },
      "name": "Set Hardcoded Targets",
      "type": "n8n-nodes-base.set",
      "typeVersion": 1,
      "position": [500, 300]
    },
    {
      "parameters": { "batchSize": 2 },
      "name": "Split Targets",
      "type": "n8n-nodes-base.splitInBatches",
      "typeVersion": 1,
      "position": [700, 300]
    },
    {
      "parameters": {
        "url": "={{$json[\"target\"]}}",
        "options": {},
        "responseFormat": "string",
        "headerParametersUi": { "parameter": [] },
        "queryParametersUi": { "parameter": [] },
        "sendBody": false
      },
      "name": "HTTP - Fetch Target",
      "type": "n8n-nodes-base.httpRequest",
      "typeVersion": 1,
      "position": [900, 300]
    },
    {
      "parameters": {
        "functionCode": "/* Analyze HTTP response, create 0..N issues per target */\nconst target = $json.target || $json.url || 'unknown';\nconst status = $json.statusCode || null;\nconst headers = $json.headers || {};\nconst body = ($json.body || '') + '';\n\nconst results = [];\n\nif (status === null) {\n  results.push({ issue: 'No response / request failed', severity: 'High', target });\n} else if (status >= 500) {\n  results.push({ issue: `HTTP ${status} — server error`, severity: 'High', target });\n} else if (status >= 400) {\n  results.push({ issue: `HTTP ${status} — client error`, severity: 'Medium', target });\n} else if (status >= 200 && status < 300) {\n  // OK — still look for fingerprints\n  // look for sensitive patterns / common admin pages / directory listing\n  const patterns = [\n    { p: /Index of \\\\//i, m: 'Directory listing detected' },\n    { p: /wp-login\\.php/i, m: 'WordPress login page found' },\n    { p: /wp-content|wp-includes/i, m: 'WordPress fingerprint' },\n    { p: /<title>phpinfo\\(\\)<\\/title>/i, m: 'phpinfo() output detected' },\n    { p: /<title>503 Service Unavailable/i, m: '503 service page' },\n    { p: /<form[^>]+admin/i, m: 'Admin form detected' },\n    { p: /<meta name=\\\\\"robots\\\\\" content=\\\\\"noindex/i, m: 'noindex meta (maybe staging)' }\n  ];\n  patterns.forEach(p=>{ if (p.p.test(body)) results.push({ issue: p.m, severity: 'High', target }) });\n}\n\n// header leakage\nconst serverHeader = headers.server || headers.Server || headers['x-powered-by'] || headers['X-Powered-By'];\nif (serverHeader) {\n  results.push({ issue: `Server header: ${serverHeader}`, severity: 'Medium', target });\n}\n\n// small heuristic: long body with 'error' word\nif (/error|exception|stack trace/i.test(body) && !/robots/i.test(body)) {\n  results.push({ issue: 'Page contains error/stack-trace-like content', severity: 'High', target });\n}\n\nreturn results.map(r => ({ json: r }));"
      },
      "name": "Analyze Response",
      "type": "n8n-nodes-base.function",
      "typeVersion": 1,
      "position": [1150, 300]
    },
    {
      "parameters": {
        "functionCode": "/* Compare with previous results and persist history to /tmp/history.json */\nconst fs = require('fs');\nconst file = '/tmp/history.json';\nlet history = {};\ntry { history = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { history = {}; }\n\nconst newItems = [];\n\n// $json contains an array of issue objects\n$json.forEach(i => {\n  const t = i.json.target;\n  const issue = i.json.issue;\n  if (!history[t]) history[t] = [];\n  if (!history[t].includes(issue)) {\n    newItems.push(i);\n    history[t].push(issue);\n  }\n});\n\nfs.writeFileSync(file, JSON.stringify(history, null, 2));\nreturn newItems;"
      },
      "name": "Compare & Persist History",
      "type": "n8n-nodes-base.function",
      "typeVersion": 1,
      "position": [1400, 300]
    },
    {
      "parameters": {
        "functionCode": "/* Group new issues per target and build simple Slack text */\nconst grouped = {};\n$json.forEach(i => {\n  const t = i.json.target;\n  if (!grouped[t]) grouped[t] = [];\n  grouped[t].push(`${i.json.severity} | ${i.json.issue}`);\n});\nreturn Object.keys(grouped).map(t => ({ json: { text: `*Target:* ${t}\\n${grouped[t].join('\\n')}` } }));"
      },
      "name": "Group For Slack",
      "type": "n8n-nodes-base.function",
      "typeVersion": 1,
      "position": [1600, 300]
    },
    {
      "parameters": {
        "url": "={{$env.SLACK_WEBHOOK}}",
        "options": {},
        "method": "POST",
        "bodyParametersJson": "={\"text\": $json[\"text\"]}",
        "headerParametersUi": { "parameter": [ { "name": "Content-type", "value": "application/json" } ] }
      },
      "name": "Slack Webhook POST",
      "type": "n8n-nodes-base.httpRequest",
      "typeVersion": 1,
      "position": [1850, 300]
    }
  ],
  "connections": {
    "Cron Every 5m": { "main": [[{ "node": "Set Hardcoded Targets", "type": "main", "index": 0 }]] },
    "Set Hardcoded Targets": { "main": [[{ "node": "Split Targets", "type": "main", "index": 0 }]] },
    "Split Targets": { "main": [[{ "node": "HTTP - Fetch Target", "type": "main", "index": 0 }]] },
    "HTTP - Fetch Target": { "main": [[{ "node": "Analyze Response", "type": "main", "index": 0 }]] },
    "Analyze Response": { "main": [[{ "node": "Compare & Persist History", "type": "main", "index": 0 }]] },
    "Compare & Persist History": { "main": [[{ "node": "Group For Slack", "type": "main", "index": 0 }]] },
    "Group For Slack": { "main": [[{ "node": "Slack Webhook POST", "type": "main", "index": 0 }]] }
  }
}
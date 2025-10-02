# 🔐 touchmark-server

---
[🇬🇧 English](#english) | [🇺🇦 Українська](#українська)

## English

### Description

`touchmark-server` is a library for verifying secure digital signatures of HTTP requests. It protects your API from unauthorized requests, timing attacks, and signature replay.

### Installation

```bash
npm install touchmark-server
```

### Purpose
- Authenticate incoming API requests
- Prevent forged requests
- Validate frontend and mobile app requests
- Validate signature

### Usage

#### 1. Initialization
```typescript
import FingerprintCore from 'touchmark-server';

const fingerprint = new FingerprintCore({
  applyFingerprint: true,
  appSecretKeyList: ['YOUR_SECRET_KEY'],
  allowedIpList: ['127.0.0.1'],
  whiteListPath: ['/api/health'],
  assetsPathPrefixList: ['/static'],
  headerSignatureKey: 'x-request-uuid'
});
```

#### 2. Express.js Integration
```typescript
const isValidSignature = (req, res, next) => {
  const { method, path, headers } = req;
  const isValid = fingerprint.decrypt({ method, path, headers });
  if (fingerprint.isFilterInit && !isValid.status) {
    return res.status(401).json({ error: 'Invalid request', details: isValid.message });
  }
  next();
};
app.use(isValidSignature);
```

#### 3. Native HTTPS Server Integration
```typescript
const server = https.createServer(options, (req, res) => {
  const method = req.method || '';
  const path = new URL(req.url || '', `https://${req.headers.host}`).pathname;
  const headers = req.headers;
  const isValid = fingerprint.decrypt({ method, path, headers });
  if (fingerprint.isFilterInit && !isValid.status) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Invalid request', details: isValid.message }));
    return;
  }
  // ...your logic
});
```

### Configuration Fields Description
- `applyFingerprint` — enable signature validation (true/false)
- `appSecretKeyList` — array of HMAC secret keys
- `allowedIpList` — array of allowed IP addresses
- `whiteListPath` — array of paths that do not require signature
- `assetsPathPrefixList` — array of static resource prefixes
- `headerSignatureKey` — header name containing the signature

### Additional
For frontend signature generation, use [touchmark-client](https://www.npmjs.com/package/touchmark-client).

---
## Українська

### Опис

`touchmark-server` — бібліотека для перевірки цифрових підписів HTTP-запитів. Захищає API від несанкціонованих запитів, таймінг-атак та повторного використання підпису.

### Встановлення

```bash
npm install touchmark-server
```

### Для чого потрібна
- Перевірка автентичності запитів
- Захист від підроблених запитів
- Валідація фронтенд, мобільних додатків
- Валідація підпису

### Використання

#### 1. Ініціалізація
```typescript
import FingerprintCore from 'touchmark-server';

const fingerprint = new FingerprintCore({
  applyFingerprint: true,
  appSecretKeyList: ['ВАШ_СЕКРЕТНИЙ_КЛЮЧ'],
  allowedIpList: ['127.0.0.1'],
  whiteListPath: ['/api/health'],
  assetsPathPrefixList: ['/static'],
  headerSignatureKey: 'x-request-uuid'
});
```

#### 2. Інтеграція з Express.js
```typescript
const isValidSignature = (req, res, next) => {
  const { method, path, headers } = req;
  const isValid = fingerprint.decrypt({ method, path, headers });
  if (fingerprint.isFilterInit && !isValid.status) {
    return res.status(401).json({ error: 'Недійсний запит', details: isValid.message });
  }
  next();
};
app.use(isValidSignature);
```

#### 3. Інтеграція з HTTPS сервером
```typescript
const server = https.createServer(options, (req, res) => {
  const method = req.method || '';
  const path = new URL(req.url || '', `https://${req.headers.host}`).pathname;
  const headers = req.headers;
  const isValid = fingerprint.decrypt({ method, path, headers });
  if (fingerprint.isFilterInit && !isValid.status) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Недійсний запит', details: isValid.message }));
    return;
  }
  // ...ваша логіка
});
```

### Опис конфігурації
- `applyFingerprint` — чи вмикати перевірку підпису (true/false)
- `appSecretKeyList` — масив секретних ключів для HMAC
- `allowedIpList` — масив дозволених IP-адрес
- `whiteListPath` — масив шляхів, які не потребують підпису
- `assetsPathPrefixList` — масив префіксів для статичних ресурсів
- `headerSignatureKey` — назва заголовка, де міститься підпис

### Додатково
Для фронтенду використовуйте [touchmark-client](https://www.npmjs.com/package/touchmark-client) для генерації підпису.

---

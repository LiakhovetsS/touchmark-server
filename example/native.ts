// example-https.ts
import https from 'node:https';
import fs from 'node:fs';
import {URL} from 'node:url';
import FingerprintCore from '../dist/index';

// Ініціалізація Fingerprint
const fingerprint = new FingerprintCore({
    applyFingerprint: true,
    appSecretKeyList: [
        'DQgjVucwuG2GEEME7muh38CPFWrQXUtNPuNvcCeLR2NWwzyaNcL7BpbKe4XY5k5b',
    ],
    allowedIpList: ['127.0.0.1', '192.168.1.1'],
    whiteListPath: ['/api/health', '/api/login'],
    assetsPathPrefixList: ['/static', '/public'],
    headerSignatureKey: 'x-request-uuid'
});

// Опції для HTTPS сервера (замініть на власні сертифікати)
const options = {
    key: fs.readFileSync('path/to/private-key.pem'),
    cert: fs.readFileSync('path/to/certificate.pem')
};

// Створення HTTPS сервера
const server = https.createServer(options, (req, res) => {
    // Отримання методу, шляху та заголовків запиту
    const method = req.method || '';
    const path = new URL(req.url || '', `https://${req.headers.host}`).pathname;
    const headers = req.headers;

    // Перевірка підпису
    //@ts-ignore
    const isValid = fingerprint.decrypt({method, path, headers});

    // Перевірка валідності запиту
    if (fingerprint.isFilterInit === true && !isValid.status) {
        res.writeHead(401, {'Content-Type': 'application/json'});
        res.end(JSON.stringify({
            error: 'Недійсний запит: відсутній або некоректний підпис',
            details: isValid.message
        }));
        return;
    }

    // Обробка різних маршрутів
    if (path === '/api/data') {
        res.writeHead(200, {'Content-Type': 'application/json'});
        res.end(JSON.stringify({message: 'Дані успішно отримані'}));
    } else {
        res.writeHead(404, {'Content-Type': 'application/json'});
        res.end(JSON.stringify({error: 'Ресурс не знайдено'}));
    }
});

// Запуск сервера
const port = 3000;
server.listen(port, () => {
    console.log(`HTTPS сервер запущено на порту ${port}`);
});

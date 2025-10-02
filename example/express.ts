// example-express.ts
//@ts-ignore
import express from 'express';
import FingerprintCore from '../dist/index.js';

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

// Створення Express додатку
const app = express();
const port = 3000;

// Middleware для перевірки підпису
//@ts-ignore
const isValidSignature = (req, res, next) => {
    try {
        const { method, path, headers } = req;
        const isValid = fingerprint.decrypt({ method, path, headers });

        if (fingerprint.isFilterInit === true && !isValid.status) {
            return res.status(401).json({
                error: 'Недійсний запит: відсутній або некоректний підпис',
                details: isValid.message
            });
        }

        next();
    } catch (ex) {
        next(ex);
    }
};

// Застосування middleware перед усіма маршрутами
app.use(isValidSignature);

// Приклад маршруту
//@ts-ignore
app.get('/api/data', (req, res) => {
    res.json({ message: 'Дані успішно отримані' });
});

// Запуск сервера
app.listen(port, () => {
    console.log(`Сервер запущено на порту ${port}`);
});

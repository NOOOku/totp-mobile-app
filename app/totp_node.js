const { authenticator } = require('otplib');

// Настраиваем параметры как в expo-totp
authenticator.options = {
    algorithm: 'sha1',
    digits: 6,
    step: 30
};

function verifyTOTP(secret, token) {
    try {
        // Нормализуем секрет
        const normalizedSecret = secret.trim().toUpperCase();
        
        // Генерируем текущий токен для отладки
        const currentToken = authenticator.generate(normalizedSecret);
        
        // Логируем для отладки
        console.log(`Secret: ${normalizedSecret}`);
        console.log(`Provided token: ${token}`);
        console.log(`Generated token: ${currentToken}`);

        // Проверяем токен
        const isValid = authenticator.verify({
            token,
            secret: normalizedSecret
        });

        return isValid;
    } catch (error) {
        console.error('Error verifying TOTP:', error);
        return false;
    }
}

// Экспортируем функцию для использования из Python
module.exports = {
    verifyTOTP
}; 
package com.n4d3sh1k4.security_service.domain.model.users;

public enum AuthProvider {
    YANDEX,     // Яндекс ID (Самый простой и стабильный)
    VK,         // VK ID (Самый массовый)
    TINKOFF,    // T-ID (Т-Банк — сейчас стандарт де-факто для e-commerce)
    SBER,       // Сбер ID (Самый тяжелый в подключении)
    LOCAL       // Логин/пароль
}

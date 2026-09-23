package com.n4d3sh1k4.security_service.dto.request_dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Schema(description = "Запрос авторизации через Яндекс (мобильный токен)")
@Data
public class YandexMobileTokenRequest {
    @Schema(description = "Access token от Яндекс OAuth", example = "y0_xxxxxxxxxxxxx")
    String accessToken;
}

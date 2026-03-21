package com.n4d3sh1k4.security_service.dto.exception_dto;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
public class ApiError {
    private int status;
    private String code;
    private String message;
    private LocalDateTime time;
}

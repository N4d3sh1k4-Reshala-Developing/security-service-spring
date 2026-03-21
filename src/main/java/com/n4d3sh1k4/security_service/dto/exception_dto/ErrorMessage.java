package com.n4d3sh1k4.security_service.dto.exception_dto;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Data
@Getter
@Setter
public class ErrorMessage {
    private int value;
    private Date date;
    private String message;
    private String userDuplicationError;

    public ErrorMessage(int value, Date date, String message, String userDuplicationError) {
        this.value = value;
        this.date = date;
        this.message = message;
        this.userDuplicationError = userDuplicationError;
    }
}

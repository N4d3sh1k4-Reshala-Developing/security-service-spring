package com.n4d3sh1k4.security_service.service;

import com.n4d3sh1k4.security_service.exception.ServerErrorException;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    private final JavaMailSender mailSender;

    @Value("${spring.mail.username}")
    private String fromEmail;

    public EmailService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    @Async
    public void sendResetTokenEmail(String to, String token) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(to);
            helper.setSubject("Восстановление пароля");

            String resetUrl = "http://localhost:3000/reset-password?token=" + token;

            String htmlContent = String.format(
                "<h1>Восстановление пароля</h1>" +
                "<p>Вы запросили смену пароля. Нажмите на кнопку ниже, чтобы продолжить:</p>" +
                "<a href='%s' style='background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;'>Сбросить пароль</a>" +
                "<p>Если вы не запрашивали смену пароля, просто проигнорируйте это письмо.</p>" +
                "<p>Ссылка действительна в течение 15 минут.</p>",
                resetUrl
            );

            helper.setText(htmlContent, true);

            mailSender.send(message);
        } catch (MessagingException e) {
            throw new ServerErrorException("Mail server unavailable");
        }
    }
}

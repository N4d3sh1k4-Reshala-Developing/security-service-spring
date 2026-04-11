package com.n4d3sh1k4.security_service.security;

import com.n4d3sh1k4.security_service.domain.model.users.User;
import com.n4d3sh1k4.security_service.jwt.JwtProvider;
import com.n4d3sh1k4.security_service.service.AuthService;
import com.n4d3sh1k4.security_service.service.UserService;
import com.n4d3sh1k4.security_service.utils.CookieUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final JwtProvider jwtProvider;
    private final CookieUtils cookieUtils;
    private final UserService userService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {


        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        String email = oAuth2User.getAttribute("default_email");

        if (email == null) {
            response.sendRedirect("http://localhost:3000/login?error=email_not_found");
            return;
        }

        String firstName = oAuth2User.getAttribute("first_name");
        String lastName = oAuth2User.getAttribute("last_name");
        String displayName = oAuth2User.getAttribute("display_name");

        if ((firstName == null || firstName.isBlank()) && (lastName == null || lastName.isBlank())) {
            if (displayName != null && !displayName.isBlank()) {
                String[] parts = displayName.trim().split("\\s+", 2);
                firstName = parts[0];
                lastName = (parts.length > 1) ? parts[1] : "";
            }
        }

        firstName = (firstName != null) ? firstName.trim() : "";
        lastName = (lastName != null) ? lastName.trim() : "";

        User user = userService.processOAuthPostLogin(email, firstName, lastName);

        String accessToken = jwtProvider.generateAccessToken(user);
        ResponseCookie refreshTokenCookie = cookieUtils.generateRefreshTokenCookie(user, true);

        response.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());

        String targetUrl = "http://localhost:3000/oauth-callback?token=" + accessToken;
        response.sendRedirect(targetUrl);
    }
}
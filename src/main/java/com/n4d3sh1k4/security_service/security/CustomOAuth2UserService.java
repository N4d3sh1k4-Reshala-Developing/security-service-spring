package com.n4d3sh1k4.security_service.security;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        String clientRegistrationId = userRequest.getClientRegistration().getRegistrationId();
        if ("vk".equalsIgnoreCase(clientRegistrationId)) {
            return loadVkUser(userRequest);
        }
        return super.loadUser(userRequest);
    }

    /**
     * VK ID требует POST https://id.vk.ru/oauth2/user_info с client_id и access_token
     * в теле (application/x-www-form-urlencoded) и отдаёт ответ вложенно:
     * {"user": {"user_id": "...", "first_name": "...", "last_name": "...", "email": "...", ...}}.
     * DefaultOAuth2UserService (GET + Bearer) для него не подходит, поэтому для VK ходим сами.
     */
    private OAuth2User loadVkUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        ClientRegistration clientRegistration = userRequest.getClientRegistration();
        String userNameAttributeName = clientRegistration
                .getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();
        String userInfoUri = clientRegistration
                .getProviderDetails().getUserInfoEndpoint().getUri();

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", clientRegistration.getClientId());
        form.add("access_token", userRequest.getAccessToken().getTokenValue());

        RequestEntity<MultiValueMap<String, String>> requestEntity = RequestEntity
                .post(userInfoUri)
                .accept(MediaType.APPLICATION_JSON)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form);

        Map<String, Object> attributes;
        try {
            ResponseEntity<Map<String, Object>> response = new RestTemplate().exchange(
                    requestEntity, new ParameterizedTypeReference<Map<String, Object>>() {});
            attributes = response.getBody();
        } catch (RestClientException ex) {
            throw invalidUserInfo("An error occurred while attempting to retrieve the user info resource: "
                    + ex.getMessage());
        }

        Map<String, Object> vkUserAttributes = extractVkUserAttributes(attributes);
        if (vkUserAttributes == null) {
            throw invalidUserInfo("Unexpected user info response structure for VK provider");
        }

        Map<String, Object> additionalParameters = userRequest.getAdditionalParameters();
        if (additionalParameters != null) {
            mergeIfAbsent(vkUserAttributes, additionalParameters, "email");
            mergeIfAbsent(vkUserAttributes, additionalParameters, "phone");
        }

        Set<GrantedAuthority> authorities = new LinkedHashSet<>();
        authorities.add(new OAuth2UserAuthority(vkUserAttributes, userNameAttributeName));
        Set<String> scopes = userRequest.getAccessToken().getScopes();
        if (scopes != null) {
            for (String scope : scopes) {
                authorities.add(new SimpleGrantedAuthority("SCOPE_" + scope));
            }
        }

        return new DefaultOAuth2User(authorities, vkUserAttributes, userNameAttributeName);
    }

    /**
     * Распаковывает тело ответа в плоскую карту с 'user_id' на верхнем уровне:
     * 1) новый формат VK ID {"user": {...}}
     * 2) legacy формат {"response": [{...}]}
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> extractVkUserAttributes(Map<String, Object> body) {
        if (body == null) {
            return null;
        }
        if (body.get("user") instanceof Map<?, ?> user) {
            return (Map<String, Object>) flatCopy(user);
        }
        if (body.get("response") instanceof List<?> responseList
                && !responseList.isEmpty()
                && responseList.get(0) instanceof Map<?, ?> firstEntry) {
            return (Map<String, Object>) flatCopy(firstEntry);
        }
        return null;
    }

    private Map<String, Object> flatCopy(Map<?, ?> source) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : source.entrySet()) {
            if (entry.getKey() instanceof String key) {
                result.put(key, entry.getValue());
            }
        }
        return result;
    }

    private void mergeIfAbsent(Map<String, Object> target, Map<String, Object> source, String key) {
        if (!target.containsKey(key) && source.containsKey(key)) {
            target.put(key, source.get(key));
        }
    }

    private OAuth2AuthenticationException invalidUserInfo(String description) {
        OAuth2Error oauth2Error = new OAuth2Error(
                "invalid_user_info_response",
                description,
                null);
        return new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
    }
}
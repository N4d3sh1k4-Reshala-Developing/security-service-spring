package com.n4d3sh1k4.security_service.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class UserGeoServiceTest {

    private UserGeoService userGeoService;
    private RestTemplate restTemplate;

    @BeforeEach
    void setUp() {
        userGeoService = new UserGeoService("http://geo.local/{ip}");
        restTemplate = mock(RestTemplate.class);
        ReflectionTestUtils.setField(userGeoService, "restTemplate", restTemplate);
    }

    @Test
    void resolveCity_nullIp_returnsNull() {
        assertThat(userGeoService.resolveCity(null)).isNull();
        assertThat(userGeoService.resolveCity(" ")).isNull();
    }

    @Test
    void resolveCity_localAddress_doesNotCallGeo() {
        assertThat(userGeoService.resolveCity("127.0.0.1")).isNull();
        assertThat(userGeoService.resolveCity("192.168.1.5")).isNull();
        assertThat(userGeoService.resolveCity("10.0.0.2")).isNull();
        assertThat(userGeoService.resolveCity("::1")).isNull();
    }

    @Test
    void resolveCity_takesFirstClientFromForwardedList() {
        whenGeo("success", "RU", "Москва");

        String result = userGeoService.resolveCity("85.140.2.55, 10.0.0.1");

        assertThat(result).isEqualTo("Москва");
    }

    @Test
    void resolveCity_apiFailure_returnsNull() {
        whenGeo("fail", "RU", null);

        assertThat(userGeoService.resolveCity("85.140.2.55")).isNull();
    }

    @Test
    void resolveCity_missingCity_returnsNull() {
        whenGeo("success", "RU", null);

        assertThat(userGeoService.resolveCity("85.140.2.55")).isNull();
    }

    @Test
    void resolveCity_apiError_returnsNull() {
        when(restTemplate.getForObject(anyString(), eq(UserGeoService.IpApiResponse.class), any(String.class)))
                .thenThrow(new RuntimeException("geo down"));

        assertThat(userGeoService.resolveCity("85.140.2.55")).isNull();
    }

    private void whenGeo(String status, String country, String city) {
        when(restTemplate.getForObject(anyString(), eq(UserGeoService.IpApiResponse.class), any(String.class)))
                .thenReturn(new UserGeoService.IpApiResponse(status, country, city));
    }
}
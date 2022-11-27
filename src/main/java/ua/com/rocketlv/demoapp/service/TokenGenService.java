package ua.com.rocketlv.demoapp.service;


import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class TokenGenService {

    public Map<String, String> generateTokens(String url, String username, Collection<? extends GrantedAuthority> lst, JwtEncoder encoder) {
        JwtClaimsSet access = JwtClaimsSet.builder()
                .issuer(url)
                .expiresAt((new Date(System.currentTimeMillis() + 1000 * 600)).toInstant())
                .subject(username)
                .claim("roles", lst.stream().map(val -> val.getAuthority().toString()).collect(Collectors.joining(" ")))
                .build();
        JwtClaimsSet refresh = JwtClaimsSet.builder()
                .issuer(url)
                .expiresAt((new Date(System.currentTimeMillis() + 1000 * 6000)).toInstant())
                .subject(username)
                .claim("roles", lst.stream().map(val -> val.getAuthority().toString()).collect(Collectors.joining(" ")))
                .build();

        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", encoder.encode(JwtEncoderParameters.from(access)).getTokenValue());
        tokens.put("refresh_token", encoder.encode(JwtEncoderParameters.from(refresh)).getTokenValue());
        return tokens;
    }
}

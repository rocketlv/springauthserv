package ua.com.rocketlv.demoapp.filter;


import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import ua.com.rocketlv.demoapp.service.MyUserPrincipal;
import ua.com.rocketlv.demoapp.service.TokenGenService;


import java.io.IOException;
import java.util.Map;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
@RequiredArgsConstructor
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private final JwtEncoder encoder;
    private final TokenGenService tokenGenService;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        log.info("Username is {} and password is {}", username, password);
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);

        return authenticationManager.authenticate(token);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication auth) throws IOException, ServletException {
        MyUserPrincipal user = (ua.com.rocketlv.demoapp.service.MyUserPrincipal) auth.getPrincipal();
        Map<String, String> tokens = tokenGenService.generateTokens (request.getRequestURL().toString(), user.getUsername(), user.getAuthorities(), encoder);
        response.setContentType(APPLICATION_JSON_VALUE);
        ObjectMapper om = new ObjectMapper();
        om.writeValue(response.getOutputStream(), tokens);
    }


}

package ua.com.rocketlv.demoapp.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import ua.com.rocketlv.demoapp.domain.Role;
import ua.com.rocketlv.demoapp.domain.User;
import ua.com.rocketlv.demoapp.service.MyUserPrincipal;
import ua.com.rocketlv.demoapp.service.TokenGenService;
import ua.com.rocketlv.demoapp.service.UserService;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.*;
import java.util.stream.Collectors;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;


@RestController
@RequiredArgsConstructor
@RequestMapping(value = "/api")
@Slf4j
public class UserResource {
    private final UserService userService;
    private final TokenGenService tokenGenService;
    private final JwtDecoder decoder;
    private final JwtEncoder encoder;

    @GetMapping("/users")
    public ResponseEntity<List<User>> getUsersList() {
        return ResponseEntity.ok().body(userService.getUsers());
    }

    @PostMapping("/user/save")
    public ResponseEntity<User> saveUser(@RequestBody User user) {
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/user/save").toUriString());
        return ResponseEntity.created(uri).body(userService.saveUser(user));
    }

    @PostMapping("/role/save")
    public ResponseEntity<Role> saveRole(@RequestBody Role role) {
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/role/save").toUriString());
        return ResponseEntity.created(uri).body(userService.saveRole(role));
    }

    @PostMapping("/role/addtouser")
    public ResponseEntity<?> addRoleToUser(@RequestBody RoleToUserForm form) {
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/role/save").toUriString());
        return ResponseEntity.created(uri).body(userService.addRoleToUser(
                form.getUsername(), form.getRole()
        ));
    }

    @PostMapping("/refresh/token")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            String header = request.getHeader(HttpHeaders.AUTHORIZATION);
            String token = header.substring("Bearer ".length());
            log.info("used token {}", token);

            Jwt decoded = decoder.decode(token);

            String username = decoded.getSubject();
            decoded.getClaims().keySet().forEach(calm->log.info((calm.intern())));
            List<String> roles = decoded.getClaimAsStringList("roles");
            Collection<SimpleGrantedAuthority> ath = new ArrayList<>();
            roles.forEach(role -> {
                ath.add(new SimpleGrantedAuthority(role));
            });

                Map<String, String> tokens = tokenGenService.generateTokens (request.getRequestURL().toString(), username, ath,encoder);

                response.setContentType(APPLICATION_JSON_VALUE);
                ObjectMapper om = new ObjectMapper();
                om.writeValue(response.getOutputStream(), tokens);

        } catch (Exception e) {
            log.error("DemoApp rise Exception {}", e.getMessage());
            response.setHeader("error", e.getMessage());
            response.setContentType(APPLICATION_JSON_VALUE);
            Map<String, String> errorMp = new HashMap<>();
            errorMp.put("error", e.getMessage());
            ObjectMapper mapper = new ObjectMapper();
            mapper.writeValue(response.getOutputStream(), errorMp);
        }
    }


    @Data
    class RoleToUserForm {
        private String username;
        private String role;
    }

}

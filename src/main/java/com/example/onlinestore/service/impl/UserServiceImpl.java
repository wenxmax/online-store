package com.example.onlinestore.service.impl;

import com.example.onlinestore.dto.LoginRequest;
import com.example.onlinestore.dto.LoginResponse;
import com.example.onlinestore.dto.PageResponse;
import com.example.onlinestore.dto.UserPageRequest;
import com.example.onlinestore.dto.UserVO;
import com.example.onlinestore.model.User;
import com.example.onlinestore.mapper.UserMapper;
import com.example.onlinestore.service.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Service
public class UserServiceImpl implements UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserServiceImpl.class);
    private final ObjectMapper objectMapper;

    public UserServiceImpl() {
        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new JavaTimeModule());
    }

    @Value("${admin.auth.username}")
    private String adminUsername;

    @Value("${admin.auth.password}")
    private String adminPassword;

    @Value("${service.user.base-url}")
    private String userServiceBaseUrl;

    private static final String AUTH_PATH = "/auth";
    private static final String TOKEN_PREFIX = "token:";
    private static final long TOKEN_EXPIRE_DAYS = 1;
    private static final long LOGIN_FAIL_TTL_MILLIS = TimeUnit.DAYS.toMillis(1);

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private UserMapper userMapper;

    @Autowired
    private StringRedisTemplate redisTemplate;

    @Autowired
    private MessageSource messageSource;

    @Override
    @Transactional
    public LoginResponse login(LoginRequest request) {
        if (adminUsername.equals(request.getUsername())) {
            if (adminPassword.equals(request.getPassword())) {
                logger.info("Admin quick login");
                resetFailedLogin(request.getUsername());
                return createLoginResponse(request.getUsername());
            } else {
                logger.warn("Invalid admin password");
                recordFailedLogin(request.getUsername());
                throw new IllegalArgumentException(messageSource.getMessage(
                    "error.invalid.credentials", null, LocaleContextHolder.getLocale()));
            }
        }

        String authUrl = UriComponentsBuilder.fromHttpUrl(userServiceBaseUrl)
            .path(AUTH_PATH)
            .toUriString();
        Boolean isAuthenticated = restTemplate.postForObject(authUrl, request, Boolean.class);
        
        if (isAuthenticated == null || !isAuthenticated) {
            recordFailedLogin(request.getUsername());
            throw new IllegalArgumentException(messageSource.getMessage(
                "error.invalid.credentials", null, LocaleContextHolder.getLocale()));
        }

        resetFailedLogin(request.getUsername());
        return createLoginResponse(request.getUsername());
    }

    private LoginResponse createLoginResponse(String username) {
        String token = UUID.randomUUID().toString();
        LocalDateTime expireTime = LocalDateTime.now().plusDays(TOKEN_EXPIRE_DAYS);

        User user = userMapper.findByUsername(username);
        if (user == null) {
            user = new User();
            user.setUsername(username);
            user.setToken(token);
            user.setTokenExpireTime(expireTime);
            user.setCreatedAt(LocalDateTime.now());
            user.setUpdatedAt(LocalDateTime.now());
            userMapper.insertUser(user);
            logger.info("Creating new user");
        } else {
            user.setToken(token);
            user.setTokenExpireTime(expireTime);
            user.setUpdatedAt(LocalDateTime.now());
            userMapper.updateUserToken(user);
            logger.info("Updating user token");
        }

        try {
            String redisKey = TOKEN_PREFIX + token;
            String userJson = objectMapper.writeValueAsString(user);
            redisTemplate.opsForValue().set(redisKey, userJson, TOKEN_EXPIRE_DAYS, TimeUnit.DAYS);
            logger.info("User information cached to Redis");
        } catch (Exception e) {
            logger.error("Failed to cache user information", e);
        }

        LoginResponse response = new LoginResponse();
        response.setToken(token);
        response.setExpireTime(expireTime);
        return response;
    }

    private UserVO convertToVO(User user) {
        if (user == null) {
            return null;
        }
        UserVO vo = new UserVO();
        vo.setId(user.getId());
        vo.setUsername(user.getUsername());
        vo.setCreatedAt(user.getCreatedAt());
        vo.setUpdatedAt(user.getUpdatedAt());
        return vo;
    }

    @Override
    public PageResponse<UserVO> listUsers(UserPageRequest request) {
        int offset = (request.getPageNum() - 1) * request.getPageSize();
        int limit = request.getPageSize();

        List<User> users = userMapper.findAllWithPagination(offset, limit);
        long total = userMapper.countTotal();

        List<UserVO> userVOs = users.stream()
                .map(this::convertToVO)
                .collect(Collectors.toList());

        PageResponse<UserVO> response = new PageResponse<>();
        response.setRecords(userVOs);
        response.setTotal(total);
        response.setPageNum(request.getPageNum());
        response.setPageSize(request.getPageSize());

        return response;
    }

    @Override
    public User getUserByToken(String token) {
        try {
            String redisKey = TOKEN_PREFIX + token;
            String userJson = redisTemplate.opsForValue().get(redisKey);
            if (userJson == null) {
                logger.warn("Invalid token");
                return null;
            }
            return objectMapper.readValue(userJson, User.class);
        } catch (Exception e) {
            logger.error("Failed to retrieve user information from Redis", e);
            return null;
        }
    }

    private void recordFailedLogin(String username) {
        try {
            String key = userFailKey(username);
            String scriptText = "local c=redis.call('INCR', KEYS[1]); redis.call('PEXPIRE', KEYS[1], ARGV[1]); return c";
            RedisScript<Long> script = new DefaultRedisScript<>(scriptText, Long.class);
            Long cnt = redisTemplate.execute(script, Collections.singletonList(key), String.valueOf(LOGIN_FAIL_TTL_MILLIS));
            logger.debug("Recorded failed login count {}", cnt);
        } catch (Exception e) {
            logger.warn("Failed to record login failure", e);
        }
    }

    private void resetFailedLogin(String username) {
        try {
            redisTemplate.delete(userFailKey(username));
        } catch (Exception e) {
            logger.warn("Failed to reset login failure counter", e);
        }
    }

    private String userFailKey(String username) {
        return "login:fail:user:" + sha256Hex(username == null ? "" : username);
    }

    private static String sha256Hex(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}

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
import org.springframework.data.redis.connection.ReturnType;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.Formatter;
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
                return createLoginResponse(request.getUsername());
            } else {
                logger.warn("Invalid admin password");
                safeRecordFailedLogin(request.getUsername());
                throw new IllegalArgumentException(messageSource.getMessage(
                    "error.invalid.credentials", null, LocaleContextHolder.getLocale()));
            }
        }

        String authUrl = UriComponentsBuilder.fromHttpUrl(userServiceBaseUrl)
            .path(AUTH_PATH)
            .toUriString();
        Boolean isAuthenticated = restTemplate.postForObject(authUrl, request, Boolean.class);
        
        if (isAuthenticated == null || !isAuthenticated) {
            safeRecordFailedLogin(request.getUsername());
            throw new IllegalArgumentException(messageSource.getMessage(
                "error.invalid.credentials", null, LocaleContextHolder.getLocale()));
        }

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

    private void safeRecordFailedLogin(String username) {
        try {
            recordFailedLogin(username);
        } catch (Exception e) {
            logger.warn("Failed to record failed login", e);
        }
    }

    private static String maskUsername(String username) {
        if (username == null || username.isEmpty()) {
            return "";
        }
        if (username.length() <= 2) {
            return "*";
        }
        return username.charAt(0) + "***" + username.charAt(username.length() - 1);
    }

    private static String sha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            Formatter formatter = new Formatter();
            for (byte b : hash) {
                formatter.format("%02x", b);
            }
            String result = formatter.toString();
            formatter.close();
            return result;
        } catch (NoSuchAlgorithmException e) {
            return "";
        }
    }

    private void recordFailedLogin(String username) {
        String normalized = username == null ? "" : username.trim().toLowerCase();
        String subjectHash = sha256(normalized);
        String key = "login:fail:user:" + subjectHash;
        String lua = "local c = redis.call('INCR', KEYS[1]); if c == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]); end return c";
        byte[] luaBytes = lua.getBytes(StandardCharsets.UTF_8);
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        byte[] ttlMsBytes = String.valueOf(TimeUnit.DAYS.toMillis(1)).getBytes(StandardCharsets.UTF_8);
        Long cnt = redisTemplate.execute(connection -> connection.eval(luaBytes, ReturnType.INTEGER, 1, keyBytes, ttlMsBytes), true);
        logger.debug("Record failed login attempt -> {}", cnt);
    }
}

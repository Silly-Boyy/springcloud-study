package com.hmall.gateway.filter;

import com.hmall.gateway.config.AuthProperties;
import com.hmall.gateway.utils.JwtTool;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.RequestPath;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
@EnableConfigurationProperties(AuthProperties.class)
@RequiredArgsConstructor
public class LoginFilter implements GlobalFilter {

    private final AuthProperties authProperties;
    private final JwtTool jwtTool;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        RequestPath path = request.getPath();
        if (isExcludePath(path.toString())) {
            return chain.filter(exchange);
        }
        List<String> authorization = request.getHeaders().get("authorization");
        String token = null;
        if (authorization != null && !authorization.isEmpty()) {
            token = authorization.get(0);
        }
        Long userId = null;
        try {
            userId = jwtTool.parseToken(token);
        } catch (Exception e) {
            ServerHttpResponse response = exchange.getResponse();
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            return response.setComplete();
        }
        String userInfo = userId.toString();
        ServerWebExchange newExchange = exchange.mutate()
                .request(builder -> builder.header("user-info", userInfo))
                .build();
        return chain.filter(newExchange);
    }

    private boolean isExcludePath(String path) {
        AntPathMatcher antPathMatcher = new AntPathMatcher();
        for (String excludePath : authProperties.getExcludePaths()) {
            if (antPathMatcher.match(excludePath, path)) {
                return true;
            }
        }
        return false;
    }
}

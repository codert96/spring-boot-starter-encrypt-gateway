package com.github.codert96.gateway;

import com.github.codert96.crypto.Encryptor;
import com.github.codert96.crypto.EncryptorKeyExtractor;
import com.github.codert96.gateway.config.WebEncryptProperties;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.factory.rewrite.ModifyResponseBodyGatewayFilterFactory;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Objects;

import static org.springframework.cloud.gateway.support.ServerWebExchangeUtils.ORIGINAL_RESPONSE_CONTENT_TYPE_ATTR;

@Slf4j
@SuppressWarnings({"UastIncorrectHttpHeaderInspection", "SpringJavaInjectionPointsAutowiringInspection"})
public class ModifyResponseBodyGatewayFilter implements GlobalFilter, Ordered {

    private static final String CSRF_HEADER = "X-Csrf-Encrypt";

    private final GatewayFilter gatewayFilter;
    private EncryptorKeyExtractor encryptorKeyExtractor;
    private WebEncryptProperties webEncryptProperties;

    public ModifyResponseBodyGatewayFilter(ModifyResponseBodyGatewayFilterFactory modifyResponseBodyGatewayFilterFactory) {
        this.gatewayFilter = modifyResponseBodyGatewayFilterFactory.apply(config -> config.setRewriteFunction(byte[].class, byte[].class, (serverWebExchange, bytes) -> {
            String originalResponseContentType = serverWebExchange.getAttribute(ORIGINAL_RESPONSE_CONTENT_TYPE_ATTR);
            if (Objects.nonNull(bytes) && bytes.length != 0 && StringUtils.hasText(originalResponseContentType)) {
                MediaType originalContentType = MediaType.parseMediaType(originalResponseContentType);
                ServerHttpResponse response = serverWebExchange.getResponse();
                HttpHeaders headers = response.getHeaders();
                if (!"ignored".equalsIgnoreCase(headers.getFirst(CSRF_HEADER)) && webEncryptProperties.getResponseContentType().stream().anyMatch(originalContentType::includes)) {
                    log.debug("开始加密：=======================================>");
                    log.debug("明文：=======================================> {}", new String(bytes));
                    Encryptor encryptor = webEncryptProperties.encryptor();
                    headers.set(CSRF_HEADER, encryptor.algorithm());
                    byte[] key = encryptorKeyExtractor.key(serverWebExchange);
                    log.debug("方式：=======================================> {}", encryptor.getClass());
                    log.debug("密钥：=======================================> {}", Base64.toBase64String(key));
                    byte[] encrypt = encryptor.encrypt(key, bytes);
                    log.debug("结果：=======================================> {}", Base64.toBase64String(encrypt));
                    headers.setContentLength(encrypt.length);
                    return Mono.justOrEmpty(encrypt);
                }
            }
            return Mono.justOrEmpty(bytes);
        }));
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        if (webEncryptProperties.isEnable()) {
            return gatewayFilter.filter(exchange, chain);
        }
        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }

    @Autowired
    public void setEncryptorKeyExtractor(EncryptorKeyExtractor encryptorKeyExtractor) {
        this.encryptorKeyExtractor = encryptorKeyExtractor;
    }

    @Autowired
    public void setWebEncryptProperties(WebEncryptProperties webEncryptProperties) {
        this.webEncryptProperties = webEncryptProperties;
    }
}

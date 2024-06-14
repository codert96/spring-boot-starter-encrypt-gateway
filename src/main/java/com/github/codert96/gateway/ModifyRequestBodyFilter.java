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
import org.springframework.cloud.gateway.filter.factory.rewrite.ModifyRequestBodyGatewayFilterFactory;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Objects;

@Slf4j
@SuppressWarnings({"UastIncorrectHttpHeaderInspection", "SpringJavaInjectionPointsAutowiringInspection"})
public class ModifyRequestBodyFilter implements GlobalFilter, Ordered {
    private static final String CSRF_HEADER = "X-Csrf-Encrypt";

    private final GatewayFilter gatewayFilter;
    private EncryptorKeyExtractor encryptorKeyExtractor;
    private WebEncryptProperties webEncryptProperties;

    public ModifyRequestBodyFilter(ModifyRequestBodyGatewayFilterFactory modifyRequestBodyGatewayFilterFactory) {
        this.gatewayFilter = modifyRequestBodyGatewayFilterFactory.apply(config -> config.setRewriteFunction(byte[].class, byte[].class, (serverWebExchange, bytes) -> {
            if (Objects.nonNull(bytes) && bytes.length != 0) {
                try {
                    Encryptor encryptor = webEncryptProperties.encryptor();
                    log.debug("开始解密：=======================================>");
                    log.debug("密文：=======================================> {}", Base64.toBase64String(bytes));
                    byte[] key = encryptorKeyExtractor.key(serverWebExchange);
                    log.debug("方式：=======================================> {}", encryptor.getClass());
                    log.debug("密钥：=======================================> {}", Base64.toBase64String(key));
                    byte[] decrypt = encryptor.decrypt(key, bytes);
                    log.debug("结果：=======================================> {}", new String(decrypt));
                    return Mono.justOrEmpty(decrypt);
                } catch (Exception e) {
                    log.error(e.getMessage(), e);
                    return Mono.error(new DecryptionFailureException(HttpStatus.UNPROCESSABLE_ENTITY, e));
                }
            }
            return Mono.justOrEmpty(bytes);
        }));
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        HttpHeaders headers = request.getHeaders();
        MediaType contentType = headers.getContentType();
        if (webEncryptProperties.isEnable()
                && !"ignored".equalsIgnoreCase(headers.getFirst(CSRF_HEADER))
                && Objects.nonNull(contentType)
                && webEncryptProperties.getRequestContentType().stream().anyMatch(contentType::includes)
        ) {
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

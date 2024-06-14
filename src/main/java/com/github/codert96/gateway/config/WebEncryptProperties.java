package com.github.codert96.gateway.config;

import com.github.codert96.crypto.Encryptor;
import com.github.codert96.crypto.impl.SM4Encryptor;
import lombok.Data;
import org.springframework.beans.BeanUtils;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.http.MediaType;

import java.beans.Transient;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Data
@ConfigurationProperties(prefix = WebEncryptProperties.PREFIX)
public class WebEncryptProperties {
    public static final String PREFIX = "spring.cloud.gateway.encrypt";

    private static final Map<Class<? extends Encryptor>, Encryptor> ENCRYPTOR_MAP = new ConcurrentHashMap<>();

    private boolean enable;

    /**
     * 需要解密的请求头
     */
    private List<MediaType> requestContentType = new ArrayList<>(Collections.singletonList(MediaType.APPLICATION_JSON));

    /**
     * 需要加密的请求头
     */
    private List<MediaType> responseContentType = new ArrayList<>(Collections.singletonList(MediaType.APPLICATION_JSON));

    /**
     * 默认使用SM4加解密，iv是密钥的reverse
     */
    private Class<? extends Encryptor> encryptor = SM4Encryptor.class;


    @Transient
    public Encryptor encryptor() {
        return ENCRYPTOR_MAP.computeIfAbsent(encryptor, BeanUtils::instantiateClass);
    }
}

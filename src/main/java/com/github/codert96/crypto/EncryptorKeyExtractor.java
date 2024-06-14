package com.github.codert96.crypto;

import org.springframework.web.server.ServerWebExchange;

public interface EncryptorKeyExtractor {
    byte[] key(ServerWebExchange serverWebExchange);
}

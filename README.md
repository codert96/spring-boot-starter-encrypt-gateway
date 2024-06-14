# spring-boot-starter-encrypt-gateway

网关Filter 对数据加解密 
yml
<pre>
spring:
  cloud:
    gateway:
      encrypt:
        enable: true
        encryptor: com.github.codert96.crypto.impl.SM4Encryptor
-------------------------------------------------------------------
@Bean
public EncryptorKeyExtractor encryptorKeyExtractor(WebEncryptProperties webEncryptProperties) {
    Encryptor encryptor = webEncryptProperties.encryptor();

    byte[] bytes = encryptor.genKey();
    System.out.println(Base64.toBase64String(bytes));
    return serverWebExchange -> bytes;

}
  
</pre>

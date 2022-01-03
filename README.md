## Spring Security OAuth2 with PKCE
* OAuth2 PKCE 
* SHA256 encryption key
* PFX asymmetric certification for JWT token

## Application default URL 👇
## https://oauth2-security-authserver.herokuapp.com/

## PFX certification for OAuth2 token
* Create command keytool -genkeypair -alias [alias_name] -keyalg RSA -keystore [filename.pfx] -storetype PKCS12 -keypass [key_password]
* Check command: keytool -list -keystore [filename.pfx] -storepass [store_password]

![image](https://user-images.githubusercontent.com/71564211/147991314-c2c83172-409c-4eb0-b673-8bb491478707.png)

## PKCE SHA-256 for OAuth2 server
* code_verifier

![image](https://user-images.githubusercontent.com/71564211/147991521-cbeee360-50e2-4bbb-aa91-89fa1b495a61.png)

* code_challenge

![image](https://user-images.githubusercontent.com/71564211/147991616-1f3f4ecf-f3f5-4513-9e19-649ddb54370b.png)

## OpenID with request param redirect_uri




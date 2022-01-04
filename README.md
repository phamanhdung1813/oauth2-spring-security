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

## OpenID scope with request param redirect_uri
* 👉 NO redirect_uri (ERROR)

### https://oauth2-security-authserver.herokuapp.com/oauth2/authorize?client_id=client1&scope=openid&response_type=code&response_mode=form_post&code_challenge=dsbodg7P8H_HWfnlRf2_SAX-AqzEYyhJDs2i5cLR6uc&code_challenge_method=S256

![image](https://user-images.githubusercontent.com/71564211/147991768-134252bd-c631-487a-b57a-e2259c5d689a.png)

* 👉 redirect_uri (authorization_code)

### https://oauth2-security-authserver.herokuapp.com/oauth2/authorize?client_id=client1&redirect_uri=https://oidcdebugger.com/debug&scope=openid&response_type=code&response_mode=form_post&code_challenge=dsbodg7P8H_HWfnlRf2_SAX-AqzEYyhJDs2i5cLR6uc&code_challenge_method=S256

![image](https://user-images.githubusercontent.com/71564211/147991830-5ffdfe2a-b6a8-4c7f-9fe8-4ed4dd4d700d.png)

![image](https://user-images.githubusercontent.com/71564211/147991926-166defb6-8b5c-46e8-8d15-6750d8a33536.png)

![image](https://user-images.githubusercontent.com/71564211/147991976-a2d33b3b-f5c9-4be8-a54f-fb513a3f276b.png)

## Other scopes (read, write,...) dont need redirect_uri

### https://oauth2-security-authserver.herokuapp.com/oauth2/authorize?client_id=client1&scope=read&response_type=code&response_mode=form_post&code_challenge=dsbodg7P8H_HWfnlRf2_SAX-AqzEYyhJDs2i5cLR6uc&code_challenge_method=S256

![image](https://user-images.githubusercontent.com/71564211/147992072-5dfa9cf9-63ca-4614-b00d-8af5f92a7239.png)

![image](https://user-images.githubusercontent.com/71564211/147992100-28e89ef4-c347-40a0-a8d8-725685bd0cde.png)

![image](https://user-images.githubusercontent.com/71564211/147992677-1fa01657-d6cc-4ba2-9328-f3eaf89d341a.png)

## OAuth2 without PKCE

### https://oauth2-security-authserver.herokuapp.com/oauth2/authorize?client_id=client1&redirect_uri=https://oidcdebugger.com/debug&scope=read&response_type=code&response_mode=form_post

![image](https://user-images.githubusercontent.com/71564211/147992232-079579f8-9c3d-4363-bcf1-cb773df8a475.png)

## NOTE
* The client sends an authorization request along with code_challenge and code_challenge_method.
* The Authorization Server notes the code_challenge, and issues the code_challenge_method the authorization code.
* The client sends an access token request along with the code_verifier.
* The Authorization Server validates the code_verifier with the received code_challenge and the code_challenge_method and issues an access token if the authentication is successful.

## Certification endpoint (PFX certification)
### https://oauth2-security-authserver.herokuapp.com/certification

![image](https://user-images.githubusercontent.com/71564211/147992553-1cd2e9c4-160f-4c0a-8761-0bd14a24be55.png)


## Refresh Token endpoint URL
![image](https://user-images.githubusercontent.com/71564211/147993311-c1f1f0d9-dec0-44d2-8c89-3f70395da634.png)

### https://oauth2-security-authserver.herokuapp.com/oauth2/token 

#### Using x-www-form-urlencoded with grant_type: refresh token and refresh_token:[refresh_token_value]

![image](https://user-images.githubusercontent.com/71564211/147993290-2055efb1-a66c-479f-b18c-053b92405157.png)

## Endpoint Security Test
![image](https://user-images.githubusercontent.com/71564211/147993493-20acf546-2489-4240-b041-14659e655059.png)

![image](https://user-images.githubusercontent.com/71564211/147993509-bdd19f50-849e-4bd7-b5af-7d655c86a53b.png)

![image](https://user-images.githubusercontent.com/71564211/147993535-a71d8748-3fbf-44d9-832b-f4ae63d8a119.png)





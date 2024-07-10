# Spring Security : Application security framework
- Login and logout functionality
- Allow/block access to URLs to logged in users
- Allow/block access to URLs to logged in users AND with certain roles
- Handles common vulnerabilities: session fixation, clickjacking, click site request forgery
# WHAT SPRING SECURITY CAN DO
- username/password authentication
- SSO/Okta/LDAP
- App level authorization
- Intra App authorization like OAuth
- Microservice security(using tokens, JWT)
- Method level security ( granular and powerful)
# 5 cores terms
1. Authentication
Answer question: " Who are you" 
- Knowledge-based authentication: 
ID + details access via username and password/pincode/answer questions

Pros: simple, effective
Cons: password can be stolen
- Possession-based authentication:
Possess something that real person will possess proven via phone/text message; keycards; access token device
- Multi factor authentication/2 factor authentication: combination of above two
2. Authorization
Answer question: should this user be allowed do what they want to do? Yes/No
-> Depends on who that user is, their roles
-> Authorization needs to be done first
3. Principle
The person you are trying to identify through the authentication: currently logged in user. Once username and password, for example, passed the authentication, the apps accepts user and create a principle and remembers it -> user doesnt need to enter username and password for every requests and page load.

One user can have multiple IDs, but there should be just one logged in user( just like how google account is)
4. Granted Authority
How does autherization happen? permissions allowed for given users -> granted authority
5. Roles 
Group of authroties assigned together so , for example, a store clerk signs in, roles are assigned to them, which is different to store manager. 

# Add Spring security to spring boot: effects and why they happen? 

1.  Dependency: spring-boot-starter-security
2. Configuration: no need to config. By adding the dependency, Spring generates log-in page and filters.Basic servlets are working underneath to provide functionalities
3. Filters: interceps every requests, like cross-cutting, checking every requests, can be applied to all urls. 
4. Default behaviour
- Adds mandatory authentication for URLs. Error pages are not secured. 
- Adds login form
- Handles login error: exammine userid and password and show message if not right
- creates a user( name 'user') and sets a default password. We can override this in application properties. For example: 
```
spring.security.user.name =kat
spring.security.user.password=pass
```
# How to config so Spring Security will refer to a list of user? 
- AuthenticationManager: it has method called authenticate() either return a successful authentication or throws error

We need to config what it does to build up pattern, not working with it directly but builder class called AuthenticaltionManagerBuilder. We need to speciy: Kind of authetication we want? memory authentication? -> we provide username, pass, roles -> a new AuthenticationManager is built. 

There is a class called ConfigureGlobal (AuthenticationManagerBuilder), it takes AuthenticationManagerBuilder as its argument. Spring Security calls configure method and pass in AuthenticationManagerBuilder. It gives developer opportunity to  override this method to create custom method take AuthenticationManagerBuilder as argument instead of using default authentication. 

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
## AuthenticationManager
-  it has method called authenticate() either return a successful authentication or throws error
- We need to config what it does to build up pattern, not working with it directly but builder class called AuthenticaltionManagerBuilder. We need to speciy: Kind of authetication we want? memory authentication? -> we provide username, pass, roles -> a new AuthenticationManager is built. 
- There is a method called ConfigureGlobal (AuthenticationManagerBuilder), it takes AuthenticationManagerBuilder as its argument. Spring Security calls configure method and pass in AuthenticationManagerBuilder. It gives developer opportunity to  override this method to create custom method take AuthenticationManagerBuilder as argument instead of using default authentication. 

```java
@EnableWebSecurity

public class SecurityConfiguration {

	private PasswordEncoder passwordEncoder;
	private UserDetailsService userDetailService;

	@Autowired
	public SecurityConfiguration(PasswordEncoder passwordEncoder, UserDetailsService userDetailService) {
		this.userDetailService = userDetailService;
		this.passwordEncoder = passwordEncoder;
	}

	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailService).passwordEncoder(passwordEncoder);
	}

}
```
- We should always have encoded/hashed passwords. In a separate class, we define the beans for PasswordEncoder and UserDetailService
```java
@Configuration
public class ConfigBean {
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		 return PasswordEncoderFactories.createDelegatingPasswordEncoder();
		

	}
	@Bean
	public UserDetailsService userDetailsService() {
		InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
		manager.createUser( User
				.withUsername("kat")
				.password(passwordEncoder()
						.encode("pass")
						)
				.roles("USER")
				.build());
		manager.createUser( User
				.withUsername("gou")
				.password(passwordEncoder()
						.encode("pass"))
				.roles("ADMIN")
				.build());
		 return manager;
		
	}
```
## EnableWebSecurity annotation 
this annotation enable support for spring security and integrate into MVC framework

## Authorization : different APIs having different levels of access control

For example, we want "/" path be accessible to everyone or unauthenticated, "/user" be accessible to User and Admin, and "/admin" only accessible to Admin

```java
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityDemoController {

	@GetMapping("/")
	public String home() {
		return("<h1>Welcome</h1>");
	}
	
	@GetMapping("/user")
	public String user() {
		return("<h1>Welcome User</h1>");
	}
	
	@GetMapping("/")
	public String admin() {
		return("<h1>Welcome Admin</h1>");
	}
}
```

- We are going to user object of type HttpSecurity, it let us configure the path and access restriction for those path. There is a  class called SecurityFilterChain which has securityFilterChain method that takes HttpSecurity as its argument. We will need to create a bean of this SecurityFilterChain class which will be utilised internally by the Spring Security framework. It represents the chain of filters that handle security-related tasks for incoming HTTP requests in application. This filters handle tasks such as authentication, authorization, CSRF protection, session management, etc. Each filter in the chain performs specific tasks and passes the request along to the next filter in the chain until the request is fully processed. 
The following config allows only authenticated users to see the greeting that matched to their roles: 

```java
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

		http.authorizeHttpRequests(
				(requests) -> requests
				.requestMatchers("/admin")
				.hasRole("ADMIN")
				.requestMatchers("/user")
				.hasAnyRole("ADMIN", "USER")
				.requestMatchers("/")
				.permitAll()
				.anyRequest()
				.authenticated()
				)
				.formLogin(
				(formLogin) -> formLogin.permitAll()
				)
				.logout(
				(logout) -> logout.permitAll()
				);

		return http.build();
```
This can be placed in to BeanConfig class defined above. 

On the screen, though we see the same login page, if we hit /admin path and login with user's credential, Spring will not allow it. Also, in order to login as user, we must logout of admin role before logging in again. 






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
# 5 core terms
1. Authentication

Answer question: " Who are you" 
- Knowledge-based authentication: 
ID + details access via username and password/pincode/answer questions

Pros: simple, effective
Cons: password can be stolen

- Possession-based authentication:
Possess something that real person will possess proven via phone/text message; keycards; access token device

- Multi factor authentication/2 factor authentication: combination of above two

**how authentication process happens**

- When you add the spring-security-starter dependency to your Spring application, it configures a filter to intercept all incoming requests (/**). This filter, called the DelegatingFilterProxy, delegates requests to various Spring Security filters, each performing specific security functions.

- One key filter is the AuthenticationFilter, which intercepts authentication requests and initiates the authentication process. This process involves verifying user credentials and is essential for securing the application. Without proper security measures, leaving parts of the application unprotected is unsafe.

**The authentication process in Spring Security involves**

- Input (User Credentials): What the user enters (e.g., username and password).
- Output (Principal): The authenticated user's details.
Spring Security tracks this process using an Authentication object. Initially, this object holds the credentials, and after authentication, it holds the principal (authenticated user details).

- The AuthenticationProvider is responsible for performing the actual authentication. It has an authenticate() method that checks the user's credentials. You need to implement this interface and its method in your application, then configure Spring Security to use your implementation. This setup ensures that Spring Security calls your authenticate() method to verify user credentials before granting access. 

- In summary, input of authentication process is of type authentication which holds credentials, then it is authenticated by method of AuthenticationProvider to return an authentication object now holds information of the current logged in user/ principle. 

- One spring security application can have multiple Authentication Provider, each provides a different authentication merchanism ( password, OAuth, LDAP)

- To cordinatate all of them we have AuthenticationManager which also have authenticate() method. Below is a method of implementing AuthenticationManager using ProviderManager: 
```java
ProviderManager implements AuthenticationManager(Authentication authentication){
    ...
}
```
-  ProviderManager finds among AuthenticationProviders which one can handle the specific authentication task using specific merchanism and delegates the work to it. 
- Each AuthenticationProvider has the supports() method to be called by ProviderManager to know what type of authentication it can support. The supports() method takes authentication as an argument and returns a boolean
- Once obtain the credentials, authenticationProvider looks up information about User from the system and compares to credentials. Spring Security retrieves that information out into its own entity called UserDetailsService. 
- UserDetailsService takes an username and returns an object with the user's details to AuthenticationProvider. This object is of type UserDetails. All the information about the user's account ( locked/unlocked, credentials, etc) is included. Once the UserDetail object is returned, the AuthenticationProvider returns the Principle with filled authorities. UserDetails object has methods such as: getAuthorities(), getPassword(), getUsername(), isAccountNonExpired(), isAccountNonLocked(), isCredentialsNonExpired(), is Enabled(). 
- Once the Authentication Filter get the  authentication object with principle, it takes the object and saves it to ThreadLocal. There is a security context associatd with the current thread. The successful authentication object is put into the security context in ThreadLocal object. There is mechanism for this context to associate with the user session so user just needs to be authenticated once and the user can access the application for the duration of the session. This is done by another filter

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

## Add Spring security to spring boot: effects and why they happen? 

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
## How to config so Spring Security will refer to a list of user? 
### AuthenticationManager
-  it has method called authenticate() either return a successful authentication or throws error
- We need to config what it does to build up pattern, not working with it directly but builder class called AuthenticaltionManagerBuilder. We need to speciy: Kind of authetication we want? memory authentication? -> we provide username, pass, roles -> a new AuthenticationManager is built. 
- There is a method called ConfigureGlobal (AuthenticationManagerBuilder), it takes AuthenticationManagerBuilder as its argument. Spring Security calls configure method and pass in AuthenticationManagerBuilder. It gives developer opportunity to  override this method to create custom method take AuthenticationManagerBuilder as argument instead of using default authentication. 
- These methods are used to define custom authentication mechanisms, like in-memory, JDBC, or LDAP authentication

- In-memory authentication: defines a set of users directly in the code for testing purposes
```java
@Autowired
public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
    auth.inMemoryAuthentication()
        .withUser("user").password(passwordEncoder().encode("password")).roles("USER")
        .and()
        .withUser("admin").password(passwordEncoder().encode("admin")).roles("ADMIN");
}
```

- JDBC Authentication: require a DataSource bean configured to point to the database
```java
@Autowired
public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
    auth.jdbcAuthentication()
        .dataSource(dataSource)
        .usersByUsernameQuery("select username, password, enabled from users where username=?")
        .authoritiesByUsernameQuery("select username, authority from authorities where username=?");
}
```
- LDAP authentication: use an LDAP server to authenticate users
```java
@Autowired
public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
    auth.ldapAuthentication()
        .userDnPatterns("uid={0},ou=people")
        .contextSource()
        .url("ldap://localhost:8389/dc=springframework,dc=org");
}
```

- Customize authentication: allows us to customize the way user details are loaded(e.g.,from a database) AND how passwords should be encoded(e.g.,using bycript to hash paswords securely)

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
 We should always have encoded/hashed passwords. In a separate class, we define the beans for PasswordEncoder and UserDetailService
```java
@Configuration
public class ConfigBean {
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		 return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}
	// call this bean to customize the in-memory data, not needed if we run from sql script
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
		 return manager; //InMemoryUserDetailsManager is a child of UserDetailsManager which is an implementation of UserDetailsService
		
	}
```
OR: 
```java
@Bean
	public InMemoryUserDetailsManager userDetailsService() {
		UserDetails user = User.builder()
							.username("kat")
							.password("pass")
							.authorities("USER")
							.build();
		UserDetails admin = User.builder()
							.username("gou")
							.password("pass")
							.authorities("ADMIN")
							.build();
		return new InMemoryUserDetailsManager(user,admin);
```
Above code using inMemory authentication, we can be more flexible by using JDBC-based authentication like this: 
```java
@Configuration
public class SecurityConfiguration {

    @Bean
    public UserDetailsService userDetailsService() {
        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                // Custom logic to load user from your data source (e.g., database)
                if ("user".equals(username)) {
                    return new User("user", "{noop}password", new ArrayList<>());
                } else {
                    throw new UsernameNotFoundException("User not found");
                }
            }
        };
    }

```
#### JdbcUserDetailsManager/InMemoryUserDetailsManager

 Other way is create a custom UserDetailsService bean in the configuration class is by using in-built implementation of UserDetailsService with JdbcUserDetailsManager and pass it the dataSource bean defined in application.properties. This is like JDBC-based authentication that it loads JDBC data source to load user details. 
 * Pros: 
 --> in-built method, just need to define a JdbcUserDetailsManager bean and configure it with a data source

 --> Use default or custom SQL queries to load user details so its quick in implementation

 * Cons:

 --> Less flexibility because it is limited to JDBC data sources and predefined SQL queries which follows format including 2 schemas: users table and authorties table with specified columns and data types. 
 Implementation: 

*  OPTION 1: call JdbcUserDetailsManager in custom UserDetailsService bean
 ```java
 @Bean
	public UserDetailsService userDetailsService() {
		JdbcUserDetailsManager manager = new JdbcUserDetailsManager();
		manager.setDataSource(dataSource);
		return manager;}
 ```
 OR :
 ```java
 @Bean
	UserDetailsManager manager(DataSource dataSource){
		JdbcUserDetailsManager users = new JdbcUserDetailsManager(dataSource);
		
		UserDetails user = User.builder()
					.username("kat")
					.password("pass")
					.authorities("USER")
					.build();
		UserDetails admin = User.builder()
					.username("gou")
					.password("pass")
					.authorities("USER","ADMIN")
					.build();
		if(!manager.userExists(user.getUsername())){
			manager.createUser(user);
		}
		if(!manager.userExists(admin.getUsername())){
			manager.createUser(admin);
		}
		return manager;
	}
* OPTION 2: Not specify any custom UserDetailsService bean, use the Jdbc-based authentication. 

```java
@Autowired
public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
    auth.jdbcAuthentication()
        .dataSource(dataSource)
        .usersByUsernameQuery("select username, password, enabled from users where username=?")
        .authoritiesByUsernameQuery("select username, authority from authorities where username=?");
}
```
Since we do not customize the UserDetailsService bean, Spring Security automatically configures a JdbcUserDetailsManager for us. the inbuilt manager loads user details from the relatinal database using predefined SQL queries. 

Here are the schema format provided by docs.spring.io: 

```sql
create table users(
	username varchar_ignorecase(50) not null primary key,
	password varchar_ignorecase(50) not null,
	enabled boolean not null
);

create table authorities (
	username varchar_ignorecase(50) not null,
	authority varchar_ignorecase(50) not null,
	constraint fk_authorities_users foreign key(username) references users(username)
);
create unique index ix_auth_username on authorities (username,authority);
```
Moreover, we can create a Custom UserDetailsService  via creating a class that implements UserDetailsService interface. UserDetailsService has a single method 'loadUserByUsername(String username) which is used by Spring Security to load user details
 ```java
 @Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException("User not found");
        }
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), new ArrayList<>());
    }
}

 ```
### EnableWebSecurity annotation 
this annotation enable support for spring security and integrate into MVC framework

## How authentication works in Spring Security?

- When we start the application, the AuthenticationFilter will pass user'credientials to AuthenticationManager, the manager picks the correct AuthenticationProvider and evoke the authenticate method while passing the authentication object with users credentials. The authenticationProvider object then call UserDetailsService to get userDetail instances from DB. The authenticationProvider nows get all what is needed for authentication process, it returns to the filter the authentication object with the Principle which is credentials already verified using DB's userDetails. 

## When multiple UserDetailsService beans are created (by mistake, not common), how can AuthenticationProvider be created?

In this case, we need to specify the instance of AuthenticationProvider with which bean of UserDetailsService we would like to implement. 

```java
@Bean
public AuthenticationProvider authenticationProvider(){
	DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
	authenticationProvider.setUserDetailsService(manager()); //use the custome JDBCUserDetailsManager provided before
	//authenticationProvider.setUserDetailsService(userDetailService()); 
	//-> this will use the in-memory UserDetailsService by default
	authenticationPrivider.setpasswordEncoder(getencoder());
}
```
## Authentication process demonstration : JDBC authentication with Spring Security and JPA

1. Config DataSource in application.properties

 We need to tell Spring that we have user credentials in our database and need to go look for username, if username matched then look for password, then if the user is valid, activated --> We need to connect the server to our database and also config DataSource bean

```
spring.application.name=SpringJDBC
spring.datasource.password=root
spring.datasource.username=root
spring.datasource.url=jdbc:mysql://localhost:3306/SSDemo?createDatabaseIfNotExist=true
spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver
```
AuthenticationProvider instance will use UserDetailService to get UserDetail instance from the database. By default, if we do not explicitly configure Spring Security to use a JDBC-based authentication mechanism or provide a custom UserDetailsService that interacts with the database, Spring Security defaults to an in-memory store for managing user credentials and roles. This behaviour ensures that developers can quickly get started with Spring Security without needing to set up a database or customer user management system. In this demonstration, we are going to use the custom UserDetailsService class and UserDetails class. 

2.  JDBC-based authentication: using custom UserDetailService and PasswordEncoder
```java
@EnableWebSecurity

public class SecurityConfiguration {
	PasswordEncoder passwordEncoder;
	UserDetailsService userDetailsService;
	
	@Autowired
	public SecurityConfiguration(PasswordEncoder passwordEncoder,UserDetailsService userDetailsService) {
		this.passwordEncoder = passwordEncoder;
		this.userDetailsService = userDetailsService;
	}
	
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		//create custom UserDetailsService -> JPA Services -> DB
		auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder)
			;
	}
```
3.  Custom PasswordEncoder
In this simple example, we are going to use plain text password ( no encoder). 
```java
@Bean
	public PasswordEncoder passwordEncoder() {
//		 return PasswordEncoderFactories.createDelegatingPasswordEncoder();
		return NoOpPasswordEncoder.getInstance();
	}
```
4. Custom UserDetailsService 
- We create a separate service class called MyUserDetailsService implementing UserDetailsService. Here we overrider the method findUserByUsername(). Inside the method, we need to do 2 things: find the User object using UserRepository and map it to the MyUserDetails implementing UserDetails dto.

```java
@Service
public class MyUserDetailsService implements UserDetailsService {
	
	@Autowired
	UserRepository userRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		//get the User object from DB
		Optional<User>user = userRepository.findByUsername(username);

		user.orElseThrow(()-> new UsernameNotFoundException("Not found: "+ username));
		//map user to MyUserDetails
		return user.map(MyUserDetails::new).get();
	
	}	
}
```java
public class MyUserDetails implements UserDetails{
	private static final long serialVersionUID = 1L;
	private String userName;
	private String password;
	private boolean active;
	private List<GrantedAuthority>authorities;

	public MyUserDetails(User user) {
		this.userName = user.getUsername();
		this.password = user.getPassword();
		this.active = user.isActive();
		this.authorities = Arrays.stream(user.getRoles().split(","))
				.map(SimpleGrantedAuthority::new) 
				.collect(Collectors.toList());
		//SimpleGrantedAuthority is a class from SpringSecurity that implements the GrantedAuthority interface. It is used to represent an authority or role granted to the user
		//when create a single user, we use: Collections.singletonList(new SimpleGrantedAuthority("ADMIN")) -  for example.
	}
	public MyUserDetails() {	
	}
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		// TODO Auto-generated method stub
		return authorities;
	}
	@Override
	public String getPassword() {
		// TODO Auto-generated method stub
		return password;
	}
	@Override
	public String getUsername() {
		// TODO Auto-generated method stub
		return userName;
	}
	 public boolean isEnabled() {
		return active;
	}
}
```
5. Create User entity model and UserRepository similar to how we normally create with other SpringBoot Project
## Authentication with LDAP
We are going to run our own instance of opensource LDAP server. This LDAP server will hold information in-memory
- Ldap data interchange format: syntax to work with ldap
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

## Json Web Tokens (JWT): for secured communication

- RFC 7519: how JWT should be structured

- HTTP: stateless protocol

When we accessing a page from a server, what information we need to send it. If it is a static HTML page, we need just URL of the page that we are looking for and the server sends us back the page. If we need another page, just send the URL. The server doesnt remember our previous requests. So if server is static and available to everyone, there is no problem in getting the pages from the server. If the server is dynamic, the server will send the information depending on who the user is. In this case, the information we send to the server just not the page you want, but also who you are. We need to provide all that infomation every time we send requests. 
 
 ### How website remember user's info  
- Session token: Reference token refers to a state on the server

like ticketing system used in customer services, when user is authenticated, the webapp creates a session and keep track of it itself. It creates a sessionId associated with the session and send back that id to user. Subsequencely, the client pass the sessionID to the server as a part of every request. The server looks it up and identifies who the client is. How the client passes sessionID to the server depends on implementation, the most common approach is to save the sessionID in a cookie so that it is automatically added on the cookie header on subsequent requests. Authentication happens, the server saves the state and returns the response for the cookie. Subsequen requests from the browser automatially have the cookie in the header because thats what browsers do. By this way, the server has info and can look it up again to identify the client. This mechanism of saving sessionID tokens saved in cookies is the most popular way for authorisation. 

- Json web token - Json object as a token: value token

Now we dont have just 1 server but multiple servers behind a load balancer. The load balancer decides which server to route the request to. This results in session info will be in memory of server1 after the first authorisation but not in server2 which handles next requests.

SOLUTION 1: All of servers might need to share a session cache (Redis) where they share the session to and look up the session from. However, this can be one single point of failure: if redirection is down, all sessions are down.  

SOLUTION 2: sticky session pattern - the load balancer will remember which server remembers the given user session info and it will redirect user to that particular server only. However this is not very scalable

SOLUTION 3: Instead of registering the session in the system and giving the client the sessionID, server records details of interaction with the client and hand it to the client.The client will bring back that record next time it sends requests to this server or other server, any other server. That server by read the record will understand and able to handle requests in the next session just like how the first server did. However, one problem is we need the record to be trustworthy, and hence the first server needs to leave a signature on that record. The next server once see the record can verify that signature if its valid. 

--> SOLUTION 3 is JWT's machenism. Now instead of server saving info state and client receiving SessionID as token, the server sends user's info as a token in Json format. When the client makes a subsequent request, the client sends the whole Json token as the request (to answer who the client is, with ID, name, whether the client is successfuly authenticated etc) which is everything the server needs. Server will first verify the signature then details. 

### Structure of JWT
3 parts (Json objects) being encoded by base64

- Header: type value of token "JWT", algorithm used to sign
- Payload: id of user in the system, name of user, issue at - to identify who the user is
- Signature: crytographic hashed

--> jwt.io to decode JWT 

When someone authenticate, the signature can only be calculated by the server using the algorithm, which after calculation will have to match the payload and header 's values. The algorithm contains a secret key so even it is out in the public only the server can compute its value. 

### JWT creation and exchange

- Server receives User's username and password, authenticate it and create a JWT after authentication is completed, then send back JWT to client.
- Client side saves JWT in local storage or in a cookie. 
- Chilent passes JWT to the server on subsiquent HTTP requests. JWT resides in HTTP header, using the Bearer schema: 
``` Authorization: Bearer <JWT>
```
- The server checks the value in the header, decode JWT 's header and payload using Base64 decode, compute them and compare with the signature on JWT. 
### How secured is JWT

- no confidential info on JWT like password, social id of user, just enough info for the server
- server just verify JWT no matter who sends it, so user must be careful about how they send JWT, such as using https protocol and other authentication and authorization mechanisms like OAuth, to make sure JWT is not be stolen
- In case JWT is stolen, server has a blacklist to invalid JWTs. This blacklist is a database or in-memory store that keeps track of invalidated JWTs. Each entry includes the token identifier and an expiration time. We can use the Token unique identifier in the token payload to track and blacklist if needed.. So in adition to verify the signature part of JWT, server will need to check for JWT blacklist as well. If its on the blacklist, server will respond with a 401 Unauthorized status code. 

## Implement JWT based authentication

**Objectives**
1. Create a new authentication API endpoint
2. Examine every incoming request for valid JWT and authorize

**dependencies**
1. Dependency to create jwt, auto validate existing jwt just like how jwt.io does
```xml
<dependency>
			<groupId>io.jsonwebtoken</groupId>
			<artifactId>jjwt</artifactId>
			<version>0.12.6</version>
</dependency>
```
2. Dependency to support Java 9+ because this will not be in the JDK

3. Create a class to verify existing token and generate token
```java
package com.demo.securityJWT;

import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

//look up info in jwt
//all jwt related
@Component
public class JwtUtil {
	/*
	 * only for testing purpose: should get the key from a setting / property file
	 * that's in a more secure location and not in source code repository.
	 */
	// CREATE A SECRETKEY
//	private static final SecretKey SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);
//	@Value("${security.jwt.secret-key:defaultValue}") // this is for keys specified in application.properties
//	private String jwtSecret = "4265656C64756E68";
//	private Key getSigningKey() {
//		byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
//		return Keys.hmacShaKeyFor(keyBytes);
//	}
	// OTHER OPTION TO CREATE KEY BY GENERATE SECRETKEY INSTANCE INSTEAD OF KEY
	// INSTANCE.
	// Using the SecretKey instance over the Key instance is advisable because the
	// new method named verifyWith() to verify the token accepts the SecretKey type
	// as a parameter
	private static final SecretKey SECRET_KEY = Jwts.SIG.HS256.key().build();

	private SecretKey getSigningKey1() {
		System.out.println("Using key: " + Base64.getEncoder().encodeToString(SECRET_KEY.getEncoded()));
		return SECRET_KEY;
	}

//	private static final SecretKey SECRET_KEY  = javax.xml.bind.DatatypeConverter.printBase64Binary(secretKey.getEncoded());

	public String extractUsername(String token) {
		return extractClaim(token, Claims::getSubject);
	}

	public Date extractExpiration(String token) {
		return extractClaim(token, Claims::getExpiration);
	}

	public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		System.out.println("I a in extractclaim");
		final Claims claims = extractAllClaims(token);
		System.out.println("done extract all claims");
		return claimsResolver.apply(claims);
	}

	private Claims extractAllClaims(String token) {
		System.out.println("I am in extract all claims");
		try {
			Claims claims = Jwts.parser().verifyWith(getSigningKey1()).build().parseSignedClaims(token).getPayload();
			System.out.println("printing the result: " + claims);
			return claims;
		} catch (Exception e) {
			System.out.println("Error parsing JWT: " + e.getMessage());
			e.printStackTrace();
			throw e; // Re-throw the exception or handle it as needed
		}
	}

	private boolean isTokenExpired(String token) {
		return extractExpiration(token).before(new Date());
	}

	// most important: taking userDetails into jwt
	public String generateToken(UserDetails userDetails) {
		Map<String, Object> claims = new HashMap<>();
		return createToken(claims, userDetails.getUsername());
	}

	private String createToken(Map<String, Object> claims, String subject) {

		return Jwts.builder().claims(claims).subject(subject).issuedAt(new Date(System.currentTimeMillis()))
				.expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10)).signWith(getSigningKey1())
				.compact();

	}

	public Boolean validateToken(String token, UserDetails userDetails) {
		final String username = extractUsername(token);

		return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
	}

}
```
4. Now we create an API endpoint that accepts userID and password and return JWT as response
```java
		
	@PostMapping("/authenticate")
	
	public ResponseEntity<?>createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception{
	try {	
		manager.authenticate(new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(),authenticationRequest.getPassword()));
	}
	catch(BadCredentialsException e){
		throw new Exception("Incorrect username and password",e);
	}
	
	final UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getUsername());
	final String jwt = jwtUtil.generateToken(userDetails);
	return ResponseEntity.ok(new AuthenticationResponse(jwt));

}
```
- We create an authenticate method with an end point that map to an authentication token (AuthenticationResponse(jwt)). The method takes in the authentication request	which is the payload in the post body contains username and password. 
- an authentication manager is used to call authenticate() method which takes UsernamePasswordAuthentiationToken as its argument. the argument is a concrete implementation of the Authentication interface thats encapsulates the user's credentials like username and password. 
- The AuthenticationManager processes the UsernamePasswordAuthenticationToken.
- If the credentials are invalid, the method throws an exception.It checks the provided username and password against the configured user details service (UserDetailsService) or other authentication providers.
- If the credentials are correct, the user is authenticated, and an Authentication object representing the authenticated user is returned.If the credentials are incorrect, an exception (such as BadCredentialsException) is thrown.
- After authentication is done, we create a jwt token using the jwtUtil that takes UserDetails objects (extracted from the system in-memory or DB) as its argument. Here we need to call an instance of UserDetails using UserDetailsService class and pass username to it. 
- The token is returned in response to browser to store in its local storage. 

NOTE: this is different to previous authentication without JWT .Here we need to call authenticate() method to authentic username and password manually before generating jwt token. 

5.  One problem is that Spring security will authenticate before letting us call /hello or /authenticate method in the controller. So we need to tell Spring to not authenticate when the web page is directed to /authenticate --> Override config method of HttpSecurity 
```java
@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

		http.csrf().disable().authorizeRequests().requestMatchers("/authenticate").permitAll().anyRequest()
				.authenticated();
		return http.build();
	}
```
- csrf().disable(): disables cross-site request forgery protection. 
- .autheorizeRequest(): allows you to configure authorization rules for different URL patterns. Following this can be:

**.requestMatchers(url_path)** :to specifies URL to which the following access rules apply; 

**.authenticated()**: requires the user to be authenticated;

**.hasRole(String role)**: requires user to have a specific role;

**.permitAll()** : allows access to everyone or not authenticated

6. When run the application, we might get an error that requires us to specify a bean of AuthenticationManager. Previously by default the authentication manager is injected and we just need to use @Autowired annotation but now its not the case anymore. To define the bean, in BeanConfig class we have:

```java
@Bean
	public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception{
	
		AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
		return authenticationManagerBuilder.build();
	}
```
This bean now can be @Autowired to use in HelloController class to call .authenticate() method. 

7. Testing via Postman

- /authentication

Specifying the header : Key -> Content-Type ; Value -> application/json
![alt text](SS/image.png)

- /hello

Specifying the header: Key -> Authorization; Value -> Bearer < jwt token copied here >

We need to tell Spring Security to listen to every request with 'Authorization' header, extract jwt from the request and username out of jwt, verify the jwt if valid then continue process with the content of jwt

### Intercept request that contains jwt
- Create a filter class that extends OncePerRequestFilter. This method looks for 'Authorization' as Key in header and Value contains 'Bearer'. It extracts the jwt token and username from Value after 'Bearer' using jwtUtil.extractUsername()
- If username is not null and no user has been authenticated, Spring Security will look into the database to get UserDetail object. This is to compare the UserDetail object from the system to jwt using jwtUtil.validateToken method. 
- If token is valid, it resumes the normal flows of Spring Security and hand off the control to the next filter in the Filter Chain
- There are two more things we need: 1) tell spring to not create a session ( because token is used to validate user now) and 2) add our Filter class so it does it job before authenticating username and password. 

```java
@Component
public class JwtRequestFilter extends OncePerRequestFilter {
	@Autowired
	JwtUtil jwtUtil;
	@Autowired
	UserDetailsService userDetailsService;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		// this has the option to pass the response to the next filter in the
		// FilterChain
		// this will need jwtUtil to verify jwt and pullout username and
		// UserDetailsService

		final String authorizationHeader = request.getHeader("Authorization");
		String username = null;
		String jwt = null;
		Map<String, Object> errorDetails = new HashMap<>();
		try {
			if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
				jwt = authorizationHeader.substring(7);
				username = jwtUtil.extractUsername(jwt);
			}
			// get the UserDetails loaded from DB/memory from this username only when
			// username can be extracted from jwt
			// and when then SecurityContext hasnot had a authenticated user
			if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
				System.out.println("username is not null and no user been authenticated yet");
				UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
				// verify if the token is validate
				System.out.println("before validate token");
				if (jwtUtil.validateToken(jwt, userDetails)) {
					// continue what Spring Security will normally do
					// set userDetails as principle
					UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
							userDetails, null, userDetails.getAuthorities());
					/**
					 * Creates a token with the supplied array of authorities.
					 * 
					 * @param authorities the collection of <tt>GrantedAuthority</tt>s for the
					 *                    principal represented by this authentication object.
					 */
					usernamePasswordAuthenticationToken
							.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
					SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);

				}
			}

		} catch (Exception e) {
			System.out.println("caught exception somehow!!");
			errorDetails.put("message", "Authentication Error");
			errorDetails.put("detail", e.getMessage());
			response.setStatus(HttpStatus.FORBIDDEN.value());
			response.setContentType(MediaType.APPLICATION_JSON_VALUE);
			ObjectMapper mapper = new ObjectMapper();
			mapper.writeValue(response.getWriter(), errorDetails);
		}
		// hand off the control to the next filter in the filter chain
		filterChain.doFilter(request, response);

		// still we need to inject it in the FilterChain
	}

}
```
Adjust SecurityFilterChain bean: 
```java
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

		http.csrf((csrf) -> csrf.ignoringRequestMatchers("/authenticate")).authorizeHttpRequests(
				(authorize) -> authorize.requestMatchers("/authenticate").permitAll().anyRequest().authenticated())
				.sessionManagement(httpSecuritySessionManagementConfigurer -> httpSecuritySessionManagementConfigurer
						.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
		// tell Spring security to not manage session or create session becaue we are
		// using Jwt to make it stateless
		// each request, SpringSecurity will set up a SecurityContext
		// we need to make sure the filter we created is used before
		// UsernamePasswordAuthenticationFilter is.
		System.out.println("I am at Security Filter Chain");
		return http.build();
	}
```
- Testing via postman: 
![alt text](SS/image1.png)






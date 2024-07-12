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
		 return manager;
		
	}
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
- Session token : like ticketing system used in customer services, when user is authenticated, the webapp creates a session and keep track of it itself. It creates a sessionId associated with the session and send back that id to user. Subsequencely, the client pass the sessionID to the server as a part of every request. The server looks it up and identifies who the client is. How the client passes sessionID to the server depends on implementation, the most common approach is to save the sessionID in a cookie so that it is automatically added on the cookie header on subsequent requests. Authentication happens, the server saves the state and returns the response for the cookie. Subsequen requests from the browser automatially have the cookie in the header because thats what browsers do. By this way, the server has info and can look it up again to identify the client. This mechanism of saving sessionID tokens saved in cookies is the most popular way for authorisation. 
- Json web token





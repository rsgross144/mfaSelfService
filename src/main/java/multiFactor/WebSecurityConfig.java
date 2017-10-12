package multiFactor;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.SAMLBootstrap;
import org.springframework.security.saml.context.SAMLContextProviderLB;
import org.springframework.security.saml.storage.EmptyStorageFactory;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;

import com.github.ulisesbocchio.spring.boot.security.saml.bean.SAMLConfigurerBean;
import com.github.ulisesbocchio.spring.boot.security.saml.bean.override.DSLWebSSOProfileConsumerImpl;

import multiFactor.BowdRoles;
import multiFactor.saml.AdfsSAMLBootstrap;
import multiFactor.saml.BowdUserDetailsService;


@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	private static final Long ONE_WEEK_SECONDS = 604800L;
	
	@Value("${app.saml.metadata-location}")
	private String idpMetaDataUrl;
	
	@Value("${app.saml.lb.server.name}")
	private String lbServerName;
	
	@Value("${app.saml.lb.server.port}")
	private Integer lbServerPort;
	
	@Value("${server.contextPath}")
	private String lbContextPath;

	@Bean
	public static SAMLBootstrap SAMLBootstrap() {
	    return new AdfsSAMLBootstrap();
	} 
	
	@Bean
	public SAMLUserDetailsService bowdUserDetailsService() {
		return new BowdUserDetailsService();
	}
	
	@Bean
	SAMLConfigurerBean saml() {
		return new SAMLConfigurerBean();
	}

	@Bean
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}
	
	

	
	
	
	@Override
    protected void configure(HttpSecurity http) throws Exception {
		SAMLContextProviderLB contextProvider = new SAMLContextProviderLB();
		contextProvider.setScheme("https");
		contextProvider.setServerName(lbServerName);
		contextProvider.setServerPort(lbServerPort);
		contextProvider.setIncludeServerPortInRequestURL(true);
		contextProvider.setContextPath(lbContextPath);
	    contextProvider.setStorageFactory(new EmptyStorageFactory());
		
		// Override, ADFS returns invalid responses if you don't lengthen this time
	    // We will set this to 1 week, though ADFS will require a login well within that
	    // timeframe
	    DSLWebSSOProfileConsumerImpl webSSOProfileConsumer = new DSLWebSSOProfileConsumerImpl();
	    webSSOProfileConsumer.setMaxAuthenticationAge(ONE_WEEK_SECONDS);
	    // the response skew accounts for difference in time between sp and idp
	    // default is 60 seconds to account for drift, had to set to 120 in local environment
	    webSSOProfileConsumer.setResponseSkew(120);  
		
	    http.httpBasic()
	    	.disable()
	    	.csrf()
	    	.disable()
	    	.anonymous()
	    .and()
	        .apply(saml())
	        .serviceProvider()
	        	.authenticationProvider()
	        		.userDetailsService(bowdUserDetailsService())
	        	.and()
	        	.ssoProfileConsumer(webSSOProfileConsumer)
	        	.samlContextProvider(contextProvider)
	    .http()
	        .authorizeRequests()
	        .requestMatchers(saml().endpointsMatcher())
	        .permitAll()
	    .and()
	        .authorizeRequests()
	        .antMatchers("/").permitAll()
	        .anyRequest()
	        	.authenticated();
    }
}

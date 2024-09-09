/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.shiro.spring.boot;

import io.buji.pac4j.context.ShiroSessionStore;
import io.buji.pac4j.filter.CallbackFilter;
import io.buji.pac4j.filter.LogoutFilter;
import io.buji.pac4j.filter.SecurityFilter;
import org.apache.shiro.biz.spring.ShiroFilterProxyFactoryBean;
import org.apache.shiro.spring.boot.pac4j.ShiroPac4jFilterFactoryBean;
import org.apache.shiro.spring.boot.pac4j.ext.filter.Pac4jUserFilter;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.spring.web.config.AbstractShiroWebFilterConfiguration;
import org.apache.shiro.web.servlet.AbstractShiroFilter;
import org.pac4j.core.config.Config;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.spring.boot.Pac4jAutoConfiguration;
import org.pac4j.spring.boot.Pac4jLogoutProperties;
import org.pac4j.spring.boot.Pac4jProperties;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


@Configuration
@AutoConfigureAfter(Pac4jAutoConfiguration.class)
@AutoConfigureBefore( name = {
	"org.apache.shiro.spring.config.web.autoconfigure.ShiroWebFilterConfiguration",  // shiro-spring-boot-web-starter
	"org.apache.shiro.spring.boot.ShiroBizWebFilterConfiguration" // spring-boot-starter-shiro-biz
})
@ConditionalOnClass({CallbackFilter.class, SecurityFilter.class, LogoutFilter.class})
@ConditionalOnProperty(prefix = ShiroPac4jProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ Pac4jProperties.class, Pac4jLogoutProperties.class, ShiroPac4jProperties.class, ShiroBizProperties.class, ServerProperties.class })
public class ShiroPac4jWebFilterConfiguration extends AbstractShiroWebFilterConfiguration implements ApplicationContextAware {

	private ApplicationContext applicationContext;

	@Autowired
	private Pac4jProperties pac4jProperties;
	@Autowired
	private Pac4jLogoutProperties logoutProperties;
	@Autowired
	private ShiroBizProperties bizProperties;
	
	@Bean
	protected SessionStore sessionStore() {
		return ShiroSessionStore.INSTANCE;
	}
	
	/**
	 * 账号注销过滤器 ：处理账号注销
	 */
	@Bean("pac4j-logout")
	public FilterRegistrationBean<LogoutFilter> logoutFilter(Config config){
		
		FilterRegistrationBean<LogoutFilter> filterRegistration = new FilterRegistrationBean<LogoutFilter>();
		
		LogoutFilter logoutFilter = new LogoutFilter();
	    
		// Whether the centralLogout must be performed（是否注销统一身份认证）
        logoutFilter.setCentralLogout(logoutProperties.isCentralLogout());
		// Security Configuration
        logoutFilter.setConfig(config);
        
        // Default logourl url
        logoutFilter.setDefaultUrl(logoutProperties.getDefaultUrl());
        // Whether the application logout must be performed（是否注销本地应用身份认证）
        logoutFilter.setLocalLogout(logoutProperties.isLocalLogout());
        // Pattern that logout urls must match（注销登录路径规则，用于匹配登录请求操作）
        logoutFilter.setLogoutUrlPattern(logoutProperties.getPathPattern());
        
        filterRegistration.setFilter(logoutFilter);
	    filterRegistration.setEnabled(false); 
	    
	    return filterRegistration;
	}
	
	/**
	 * 权限控制过滤器 ：实现权限认证
	 */
	@Bean("pac4j")
	public FilterRegistrationBean<SecurityFilter> pac4jSecurityFilter(Config config){
		
		FilterRegistrationBean<SecurityFilter> filterRegistration = new FilterRegistrationBean<SecurityFilter>();
		
		SecurityFilter securityFilter = new SecurityFilter();  
		
		// List of authorizers
		securityFilter.setAuthorizers(pac4jProperties.getAuthorizers());
		// List of clients for authentication
		securityFilter.setClients(pac4jProperties.getClients());
		// Security configuration
		securityFilter.setConfig(config);
		securityFilter.setMatchers(pac4jProperties.getMatchers());
		
        filterRegistration.setFilter(securityFilter);
	    filterRegistration.setEnabled(false); 
	    
	    return filterRegistration;
	}
	
	
	@Bean("pac4j-user")
	public FilterRegistrationBean<Pac4jUserFilter> pac4jUserFilter(){
		FilterRegistrationBean<Pac4jUserFilter> registration = new FilterRegistrationBean<Pac4jUserFilter>(); 
		Pac4jUserFilter userFilter = new Pac4jUserFilter();
		userFilter.setLoginUrl(pac4jProperties.getLoginUrl());
		registration.setFilter(userFilter);
	    registration.setEnabled(false); 
	    return registration;
	}
	
	
	/**
	 * 回调过滤器 ：处理登录后的回调访问
	 */
	@Bean("pac4j-callback")
	public FilterRegistrationBean<CallbackFilter> callbackFilter(Config config){
		
		FilterRegistrationBean<CallbackFilter> filterRegistration = new FilterRegistrationBean<CallbackFilter>();
		
	    CallbackFilter callbackFilter = new CallbackFilter();
	    
	    // Security Configuration
        callbackFilter.setConfig(config);
        // Default url after login if none was requested（登录成功后的重定向地址，等同于shiro的successUrl）
        callbackFilter.setDefaultUrl(pac4jProperties.getLoginUrl());
        
        filterRegistration.setFilter(callbackFilter);
	    filterRegistration.setEnabled(false); 
	    
	    return filterRegistration;
	}
	
	/**
	 * 权限控制过滤器 ：权限过滤链的入口（仅是FactoryBean需要引用）
	 */
	@Bean
    @Override
	protected ShiroFilterFactoryBean shiroFilterFactoryBean() {

		ShiroFilterProxyFactoryBean filterFactoryBean = new ShiroPac4jFilterFactoryBean();
		filterFactoryBean.setStaticSecurityManagerEnabled(bizProperties.isStaticSecurityManagerEnabled());
		
		// 登录地址：会话不存在时访问的地址
		filterFactoryBean.setLoginUrl(pac4jProperties.getLoginUrl());
		// 系统主页：登录成功后跳转路径
		filterFactoryBean.setSuccessUrl(bizProperties.getSuccessUrl());
		// 异常页面：无权限时的跳转路径
		filterFactoryBean.setUnauthorizedUrl(bizProperties.getUnauthorizedUrl());
		
		// 必须设置 SecurityManager
		filterFactoryBean.setSecurityManager(securityManager);
		// 拦截规则
		filterFactoryBean.setFilterChainDefinitionMap(shiroFilterChainDefinition.getFilterChainMap());
		
		return filterFactoryBean;
	}
	
	/**
	 * 权限控制过滤器 ：权限过滤链的入口
	 */
	@Bean(name = "filterShiroFilterRegistrationBean")
    protected FilterRegistrationBean<AbstractShiroFilter> filterShiroFilterRegistrationBean() throws Exception {

        FilterRegistrationBean<AbstractShiroFilter> filterRegistrationBean = new FilterRegistrationBean<AbstractShiroFilter>();
        filterRegistrationBean.setFilter((AbstractShiroFilter) shiroFilterFactoryBean().getObject());
        filterRegistrationBean.setOrder(1);

        return filterRegistrationBean;
    }
    
    @Override
  	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
  		this.applicationContext = applicationContext;
  	}

  	public ApplicationContext getApplicationContext() {
  		return applicationContext;
  	}
    
}

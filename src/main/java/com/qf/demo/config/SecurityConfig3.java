package com.qf.demo.config;


import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;

import javax.sql.DataSource;
import java.io.PrintWriter;

/**
 * @Author lzj
 * @Date 2021/10/18
 * 设置登录账户方式二：配置类
 */
@Configuration
public class SecurityConfig3 extends WebSecurityConfigurerAdapter {

    @Bean
    PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }


    @Autowired
    DataSource dataSource;
    /**
     * 配置用户信息
     * @param
     * @throws Exception
     */
    @Override
    @Bean
    protected UserDetailsService userDetailsService(){
        JdbcUserDetailsManager manager = new JdbcUserDetailsManager();
        manager.setDataSource(dataSource);
        if (!manager.userExists("javaboy")) {
            manager.createUser(User.withUsername("javaboy").password("123").roles("admin").build());
        }
        if (!manager.userExists("lzj")) {
            manager.createUser(User.withUsername("lzj").password("123").roles("user").build());
        }
        return manager;
    }

    /**
     * 角色继承 admin拥有user的权限
     */
    @Bean
    RoleHierarchy roleHierarchy(){
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_admin > ROLE_user");
        return roleHierarchy;
    }

    /**
     * 管理静态资源
     * @param web
     * @throws Exception
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        //放行静态资源
        web.ignoring().antMatchers("/js/**","/images/**","/css/**");
    }

    /**
     * 管理请求响应
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/admin/**").hasRole("admin")
                .antMatchers("/user/**").hasRole("user")
                .anyRequest().authenticated() //所有请求都要验证
                .and()
                .formLogin()//表单登录
                .loginProcessingUrl("/doLogin")//配置登录接口,如果没有配置就是loginPage的参数
                //前后端分离 登录成功或者失败跳转页面只返回json
                //成功
                .successHandler((req,resp, authentication) ->{
                    resp.setContentType("application/json,charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    //返回用户登录的信息
                    out.write(new ObjectMapper().writeValueAsString(authentication.getPrincipal()));
                    out.flush();
                    out.close();
                })
                //失败
                .failureHandler((req,resp,exception)->{
                    resp.setContentType("application/json;charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    //返回用户登录的信息
                    out.write(new ObjectMapper().writeValueAsString(exception.getMessage()));
                    out.flush();
                    out.close();
                })
                .permitAll() //放行
                .and()
                //注销
                .logout()
                .logoutUrl("/logout") //注销地址 get请求
                .logoutSuccessHandler((req,resp, authentication)->{
                    resp.setContentType("application/json;charset=utf-8");
                    resp.setStatus(401);
                    PrintWriter out = resp.getWriter();
                    //返回用户登录的信息
                    out.write(new ObjectMapper().writeValueAsString("注销登录成功！"));
                    out.flush();
                    out.close();
                })
                .permitAll()
                .and()
                .csrf().disable() //关闭跨域
                //未认证登录返回json数据 不跳转页面 无状态登录
                .exceptionHandling()
                .authenticationEntryPoint((req,resp,exception)->{
                    resp.setContentType("application/json;charset=utf-8");
                    resp.setStatus(401);
                    PrintWriter out = resp.getWriter();
                    //返回用户登录的信息
                    out.write(new ObjectMapper().writeValueAsString("尚未登录，请先登录"));
                    out.flush();
                    out.close();
                });


    }
}

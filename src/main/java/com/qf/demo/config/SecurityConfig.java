package com.qf.demo.config;


import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.PrintWriter;

/**
 * @Author lzj
 * @Date 2021/10/18
 * 设置登录账户方式二：配置类
 */
//@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }

    /**
     * 配置用户信息
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //在内存中存储
           auth.inMemoryAuthentication()
                   .withUser("javaboy")
                   .password("123")
                   .roles("admin");//用户名权限
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
                .anyRequest().authenticated() //所有请求都要验证
                .and()
                .formLogin()//表单登录
                .loginPage("/login.html")//登录页面 默认/login
                .loginProcessingUrl("/doLogin")//配置登录接口,如果没有配置就是loginPage的参数
                //登录参数自定义 默认username、password
                .usernameParameter("name")
                .passwordParameter("pwd")
                //指定登录成功跳转页面
                //转发
//                .successForwardUrl("/success")
                //重定向 会记录重定向之前的位置，退出之后直接回到记录的位置，而转发不会
                //比如京东的购物车，结算时跳转到登录页面，成功之后直接返回结算页面
                //登录失败
                //转发
//                .failureForwardUrl()
                //重定向
//                .failureUrl()
//                .defaultSuccessUrl("/success")
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
//                .logoutRequestMatcher(new AntPathRequestMatcher("/logout","POST")) 注销改成post请求
//                .logoutSuccessUrl("/login.html") //注销成功之后跳转到登录页面
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

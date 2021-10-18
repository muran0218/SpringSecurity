package com.qf.demo.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @Author lzj
 * @Date 2021/10/18
 */
@RestController
public class HelloController {

    @RequestMapping("/hello")
    public String hello(){
        return "javaBoy";
    }

    @RequestMapping("/success")
    public String success(){
        return "success";
    }


    @RequestMapping("/admin/hello")
    public String admin(){
        return "admin";
    }

    @RequestMapping("/user/hello")
    public String user(){
        return "user";
    }
}

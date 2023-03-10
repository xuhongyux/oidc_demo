package com.xiayu.authorize.controller;

/**
 * @author xuhongyu
 * @create 2023-03-10 15:47
 */
public class UserInfoRes {

    public UserInfoRes(String username,String email ){
        this.username = username;
        this.email = email;
    }
    private String username;

    private String email;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }
}

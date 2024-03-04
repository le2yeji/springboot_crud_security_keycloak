package com.kt.edu.thirdproject.employee.domain;

public class SigninRequest {
    private String username;
    private String password;

    public SigninRequest() {
    }

    public SigninRequest(String username, String password) {
        this.username = username;
        this.password = password;
    }

    // Getter와 Setter 메서드
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}

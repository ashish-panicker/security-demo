package com.example.security_demo.security.model;

import jakarta.persistence.*;

import java.util.*;

@Entity
@Table(name = "app_users")
public class AppUser{

    @Id
    private String userName; //user_name

    private String password;

    private String email;

    private boolean isExpired = false;

    private boolean isLocked = false;

    @Column(name = "credentials_expired")
    private boolean isCredentialsExpired = false;

    private boolean isEnabled = true;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "app_users_roles", joinColumns = @JoinColumn(name = "userName"))
    @Column(name = "role")
    private Set<String> roles = new HashSet<>();

    public AppUser() {
    }

    public AppUser(String userName, String password, String email, Set<String> roles) {
        this.userName = userName;
        this.password = password;
        this.email = email;
        this.roles = roles;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public boolean isExpired() {
        return isExpired;
    }

    public void setExpired(boolean expired) {
        isExpired = expired;
    }

    public boolean isLocked() {
        return isLocked;
    }

    public void setLocked(boolean locked) {
        isLocked = locked;
    }

    public boolean isCredentialsExpired() {
        return isCredentialsExpired;
    }

    public void setCredentialsExpired(boolean credentialsExpired) {
        isCredentialsExpired = credentialsExpired;
    }

    public boolean isEnabled() {
        return isEnabled;
    }

    public void setEnabled(boolean enabled) {
        isEnabled = enabled;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public void setRoles(Set<String> roles) {
        this.roles = roles;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        AppUser appUser = (AppUser) o;
        return isExpired == appUser.isExpired && isLocked == appUser.isLocked &&
                isCredentialsExpired == appUser.isCredentialsExpired &&
                isEnabled == appUser.isEnabled && Objects.equals(userName, appUser.userName) &&
                Objects.equals(password, appUser.password) && Objects.equals(email, appUser.email) &&
                Objects.equals(roles, appUser.roles);
    }

    @Override
    public int hashCode() {
        return Objects.hash(userName, password, email, isExpired, isLocked, isCredentialsExpired, isEnabled, roles);
    }
}

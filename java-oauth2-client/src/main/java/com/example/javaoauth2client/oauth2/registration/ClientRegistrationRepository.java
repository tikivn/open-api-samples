package com.example.javaoauth2client.oauth2.registration;

public interface ClientRegistrationRepository {
    ClientRegistration findByRegistrationId(String var1);
}

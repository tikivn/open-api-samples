package com.example.javaoauth2client.oauth2.registration;


import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryClientRegistrationRepository implements ClientRegistrationRepository, Iterable<ClientRegistration> {
    private final Map<String, ClientRegistration> registrations;

    public InMemoryClientRegistrationRepository(ClientRegistration... registrations) {
        this(Arrays.asList(registrations));
    }

    public InMemoryClientRegistrationRepository(List<ClientRegistration> registrations) {
        this(createRegistrationsMap(registrations));
    }

    private static Map<String, ClientRegistration> createRegistrationsMap(List<ClientRegistration> registrations) {
        return toUnmodifiableConcurrentMap(registrations);
    }

    private static Map<String, ClientRegistration> toUnmodifiableConcurrentMap(List<ClientRegistration> registrations) {
        ConcurrentHashMap<String, ClientRegistration> result = new ConcurrentHashMap<>();

        for (ClientRegistration registration : registrations) {
            result.put(registration.getRegistrationId(), registration);
        }

        return Collections.unmodifiableMap(result);
    }

    public InMemoryClientRegistrationRepository(Map<String, ClientRegistration> registrations) {
        this.registrations = registrations;
    }

    public Iterator<ClientRegistration> iterator() {
        return this.registrations.values().iterator();
    }

    @Override
    public ClientRegistration findByRegistrationId(String registrationId) {
        return this.registrations.get(registrationId);
    }
}
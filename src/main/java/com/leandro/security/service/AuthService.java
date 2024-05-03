package com.leandro.security.service;

import com.leandro.security.controller.models.AuthResponse;
import com.leandro.security.controller.models.AuthenticationRequest;
import com.leandro.security.controller.models.RegisterRequest;

public interface AuthService {

    AuthResponse register(RegisterRequest request);
    AuthResponse authenticate(AuthenticationRequest request);

}

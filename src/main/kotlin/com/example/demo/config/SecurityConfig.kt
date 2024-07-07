package com.example.demo.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.ProviderManager
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.context.HttpSessionSecurityContextRepository
import org.springframework.security.web.context.SecurityContextRepository

@Configuration
@EnableWebSecurity
class SecurityConfig {
  @Bean
  fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
    http {
      csrf { disable() }
      authorizeHttpRequests {
        authorize("/login", permitAll)
        authorize(anyRequest, authenticated)
      }
      sessionManagement {
        sessionCreationPolicy = SessionCreationPolicy.ALWAYS
      }
    }
    return http.build()
  }

  @Bean
  fun authenticationManager(
    userDetailsService: UserDetailsService,
    passwordEncoder: PasswordEncoder,
  ): AuthenticationManager {
    val authenticationProvider = DaoAuthenticationProvider()
    authenticationProvider.setUserDetailsService(userDetailsService)
    authenticationProvider.setPasswordEncoder(passwordEncoder)

    return ProviderManager(authenticationProvider)
  }

  @Bean
  fun securityContextRepository(): SecurityContextRepository = HttpSessionSecurityContextRepository()

  @Bean
  fun userDetailsService(): UserDetailsService {
    val user = User.withDefaultPasswordEncoder()
      .username("user")
      .password("password")
      .roles("USER")
      .build()

    return InMemoryUserDetailsManager(user)
  }

  @Bean
  fun passwordEncoder(): PasswordEncoder {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder()
  }
}
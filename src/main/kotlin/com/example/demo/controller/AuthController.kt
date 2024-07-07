package com.example.demo.controller

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.User
import org.springframework.security.web.context.SecurityContextRepository
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController

data class LoginRequest(
  val username: String,
  val password: String,
)

data class UserInfoResponse(
  val principal: User,
  val authorities: String,
)

@RestController
class AuthController(
  private val authManager: AuthenticationManager,
  private val securityContextRepository: SecurityContextRepository,
) {
  @PostMapping("/login")
  fun login(@RequestBody login: LoginRequest, request: HttpServletRequest, response: HttpServletResponse): String {
    val authentication = authManager.authenticate(
      UsernamePasswordAuthenticationToken(login.username, login.password)
    )
    val context = SecurityContextHolder.createEmptyContext()
    context.authentication = authentication
    SecurityContextHolder.setContext(context)
    securityContextRepository.saveContext(context, request, response)
    return "Login Success"
  }

  @GetMapping("/me")
  fun getUserInfo(): UserInfoResponse {
    val authentication = SecurityContextHolder.getContext().authentication
    val principal = authentication.principal as User
    val authorities = authentication.authorities.toString()
    return UserInfoResponse(principal, authorities)
  }
}
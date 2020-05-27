package com.example.security.springsecurityJWT.filters;

import com.example.security.springsecurityJWT.jwt.JwtUtil;
import com.example.security.springsecurityJWT.services.MyUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {


    @Autowired
    private MyUserDetailsService myUserDetailsService;

    @Autowired
    private JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain)
            throws ServletException, IOException {

           String authorizeHeader = httpServletRequest.getHeader("Authorization");

           String username = null;
           String Jwt = null;

           if(authorizeHeader != null && authorizeHeader.startsWith("Bearer "))
           {
               Jwt = authorizeHeader.substring(7);
               username = jwtUtil.extractUsername(Jwt);
           }

           if(username != null && SecurityContextHolder.getContext().getAuthentication() == null)
           {
               UserDetails userDetails = myUserDetailsService.loadUserByUsername(username);
               if(jwtUtil.validateToken(Jwt,userDetails))
               {
                   UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                           userDetails,null,userDetails.getAuthorities()
                   );

                   usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));
                   SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);

               }
           }
        filterChain.doFilter(httpServletRequest,httpServletResponse);

    }
}

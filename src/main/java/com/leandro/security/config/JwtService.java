package com.leandro.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY = "306d6f5f762351305c683e2042663433653335245151674f78416959333a4f28295878417d69476d6526347e515f7635792e4a4f7159597264306c383d3422";


    public String generateToken(UserDetails userDetails){
       return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(Map<String, Objects> extraClaim, UserDetails userDetails){
        return Jwts.builder()
                .claims()
                .add(extraClaim)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 24))
                .and()
                .signWith(getSignInKey(), Jwts.SIG.HS256)
                .compact();
    }

    public String getUserName(String token) {
        return getClaim(token, Claims::getSubject);
    }

    public <T> T getClaim(String token, Function<Claims,T> claimsResolver){
        final Claims claims = getAllClams(token);
        return claimsResolver.apply(claims);
    }

    private Claims getAllClams(String token) {
        return  Jwts.parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();

    }

    private SecretKey getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }


    public boolean validateToken(String token, UserDetails userDetails) {
        final String username = getUserName(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        return getExpiration(token).before(new Date());
    }

    private Date getExpiration(String token) {
        return  getClaim(token, Claims::getExpiration);
    }
}

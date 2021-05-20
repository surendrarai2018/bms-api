package com.bms.user.model;

import java.io.Serializable;

public class JwtResponse implements Serializable {

	private static final long serialVersionUID = -8091879091924046844L;

	// private final String jwttoken;
	private String token;
	private String type;
	// private Long id;
	private String username;

	// private String email;
	public JwtResponse(String token, String username) {
		super();
		this.token = token;
		this.username = username;
	}

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

}
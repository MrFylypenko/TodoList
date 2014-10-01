package com.todolist.service;

import java.util.List;

import com.todolist.model.User;

public interface UserService {
	
	public List<User> getAllUsers();

	public void addUser(User user);
	
	public User findByUserName(String username);
	
	public String encode (String pass);

	
}

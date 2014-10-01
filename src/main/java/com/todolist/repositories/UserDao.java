package com.todolist.repositories;

import java.util.List;

import com.todolist.model.User;

public interface UserDao {

	public void addUser(User user);

	public List<User> getAllUsers();

	public User findByUserName(String username);

	public String encode(String pass);

}

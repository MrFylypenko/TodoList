package com.todolist.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.todolist.model.UserRole;
import com.todolist.repositories.UserRoleDao;

@Service
public class UserRoleServiceImpl implements UserRoleService {

	@Autowired
	UserRoleDao userRoleDao;

	@Override
	public void addUserRole(UserRole userRole) {
		userRoleDao.addUserRole(userRole);
	}

}

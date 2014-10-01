package com.todolist.repositories;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.todolist.model.UserRole;

@Repository
public class UserRoleDaoImpl implements UserRoleDao{

	@PersistenceContext
	private EntityManager entityManager;
	
	@Override
	@Transactional
	public void addUserRole(UserRole userRole) {
		entityManager.persist(userRole);
		
	}

}

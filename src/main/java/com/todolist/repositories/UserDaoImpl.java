package com.todolist.repositories;

import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.todolist.model.User;

@Repository
public class UserDaoImpl implements UserDao {

	@PersistenceContext
	private EntityManager entityManager;

	public String encode(String pass) {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		String result = encoder.encode(pass);
		return result;
	}

	@Override
	@Transactional
	public void addUser(User user) {
		entityManager.persist(user);
	}

	@Override
	@Transactional
	public List<User> getAllUsers() {

		@SuppressWarnings("unchecked")
		List<User> result = entityManager.createNamedQuery("selectAllUsers")
				.getResultList();

		return result;
	}

	@Override
	@Transactional
	public User findByUserName(String username) {
		User user = entityManager.find(User.class, username);
		return user;
	}

}

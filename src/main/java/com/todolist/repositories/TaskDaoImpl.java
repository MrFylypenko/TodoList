package com.todolist.repositories;

import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.todolist.model.Task;

@Repository
public class TaskDaoImpl implements TaskDao {

	@PersistenceContext
	private EntityManager entityManager;

	@Override
	@Transactional
	public List<Task> getAllTasks() {

		@SuppressWarnings("unchecked")
		List<Task> tasks = entityManager.createNativeQuery(
				"SELECT * FROM task", Task.class).getResultList();

		return tasks;
	}

	@Override
	@Transactional
	public void addTask(Task task) {
		System.out.println(task);
		entityManager.persist(task);
	}

	@Override
	@Transactional
	public void updateTask(Task task) {
		entityManager.merge(task);
	}

	@Override
	@Transactional
	public void deleteTask(Integer idTask) {
		Task task = entityManager.find(Task.class, idTask);
		entityManager.remove(task);
	}

	@Override
	@Transactional
	public Task findTaskById(Integer idTask) {
		return entityManager.find(Task.class, idTask);
	}

}

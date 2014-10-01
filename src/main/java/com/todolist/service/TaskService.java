package com.todolist.service;

import java.util.List;

import com.todolist.model.Task;

public interface TaskService {

	public List<Task> getAllTasks();

	public void addTask(Task task);

	public void updateTask(Task task);

	public void deleteTask(Integer idTask);
	
	public Task findTaskById (Integer idTask);

}

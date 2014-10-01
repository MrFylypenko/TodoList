package com.todolist.repositories;

import java.util.List;

import com.todolist.model.Task;

public interface TaskDao {

	public List<Task> getAllTasks();

	public void addTask(Task task);

	public void updateTask(Task task);

	public void deleteTask(Integer idTask);

	public Task findTaskById(Integer idTask);

}

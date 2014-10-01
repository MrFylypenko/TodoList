package com.todolist.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.todolist.model.Task;
import com.todolist.repositories.TaskDao;

@Service
public class TaskServiceImpl implements TaskService {

	@Autowired
	TaskDao taskdao;

	@Override
	public List<Task> getAllTasks() {
		return taskdao.getAllTasks();
	}

	@Override
	public void addTask(Task task) {
		taskdao.addTask(task);

	}

	@Override
	public void updateTask(Task task) {
		taskdao.updateTask(task);

	}

	@Override
	public void deleteTask(Integer idTask) {
		taskdao.deleteTask(idTask);
	}

	@Override
	public Task findTaskById(Integer idTask) {
		return taskdao.findTaskById(idTask);
	}

}

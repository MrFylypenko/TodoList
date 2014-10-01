package com.todolist.myapp;

import static org.junit.Assert.*;

import java.util.Date;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.todolist.model.Task;
import com.todolist.model.User;
import com.todolist.service.TaskService;
import com.todolist.service.UserRoleService;
import com.todolist.service.UserService;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = { "file:src/test/resources/META-INF/test-application-context.xml" })
public class RepositoryTest {

	@Autowired
	UserService userService;

	@Autowired
	TaskService taskService;

	@Autowired
	UserRoleService userRoleService;

	@Test
	public void testUserService() {

		User user = new User();
		user.setEnabled(true);
		user.setPassword("password");
		user.setConfirmPassword("password");
		user.setUsername("username");
		user.setEmail("email@email.com");

		userService.addUser(user);
		List<User> users = userService.getAllUsers();

		assertNotNull(users.get(0).getUsername() == "username");
	}

	@Test
	public void testTaskService() {

		Task task = new Task();

		task.setDate(new Date());
		task.setDescription("test Description");
		task.setPerformer("test Performer");
		task.setResolved(true);
		task.setResult("test Result");
		task.setTitle("test Title");
		task.setUser("test User");

		taskService.addTask(task);

		List<Task> tasks = taskService.getAllTasks();
		assertNotNull(tasks);
	}

}

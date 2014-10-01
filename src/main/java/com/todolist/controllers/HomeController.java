package com.todolist.controllers;

import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import com.todolist.model.Task;
import com.todolist.model.User;
import com.todolist.model.UserRole;
import com.todolist.service.TaskService;
import com.todolist.service.UserRoleService;
import com.todolist.service.UserService;

/**
 * Handles requests for the application home page.
 */
@Controller
@RequestMapping(value = "/")
public class HomeController {

	@Autowired
	UserService userService;

	@Autowired
	TaskService taskService;

	@Autowired
	UserRoleService userRoleService;

	@RequestMapping(value = "/", method = RequestMethod.GET)
	public String home(Locale locale, Model model) {
		return "redirect:/index";
	}

	@RequestMapping(value = "/index", method = RequestMethod.GET)
	public String index(Model model, HttpServletRequest request) {

		Map<String, String> mapUsers = new LinkedHashMap<String, String>();
		List<User> users = userService.getAllUsers();
		for (User user : users) {
			mapUsers.put(user.getUsername(), user.getUsername());
		}
		List<Task> tasks = taskService.getAllTasks();

		Task task = new Task();

		if (request.getRemoteUser() != null) {
			task.setUser(request.getRemoteUser());
		}

		model.addAttribute("tasks", tasks);
		model.addAttribute("mapUsers", mapUsers);
		model.addAttribute("task", task);
		model.addAttribute("page", "task.jsp");
		return "index";
	}

	@RequestMapping(value = "/index", method = RequestMethod.POST)
	public String indexPost(@Valid Task task, BindingResult result,
			Model model, HttpServletRequest request) {

		if (!result.hasErrors()) {
			task.setDate(new Date());
			task.setResult("");
			task.setResolved(false);
			taskService.addTask(task);
			task = new Task();
		}
		Map<String, String> mapUsers = new LinkedHashMap<String, String>();
		List<User> users = userService.getAllUsers();
		for (User user : users) {
			mapUsers.put(user.getUsername(), user.getUsername());
		}

		if (request.getRemoteUser() != null) {
			task.setUser(request.getRemoteUser());
		}
		List<Task> tasks = taskService.getAllTasks();

		model.addAttribute("task", task);
		model.addAttribute("tasks", tasks);
		model.addAttribute("mapUsers", mapUsers);
		model.addAttribute("page", "task.jsp");
		return "index";
	}

	@RequestMapping(value = "/taskdelete/{idTask}")
	public String deleteTask(@PathVariable("idTask") Integer idTask) {
		taskService.deleteTask(idTask);
		return "redirect:/index";
	}

	@RequestMapping(value = "/taskedit/{idTask}", method = RequestMethod.GET)
	public String taskEdit(@PathVariable("idTask") Integer idTask, Model model) {

		Map<String, String> mapUsers = new LinkedHashMap<String, String>();
		List<User> users = userService.getAllUsers();
		for (User user : users) {
			mapUsers.put(user.getUsername(), user.getUsername());
		}

		Task task = taskService.findTaskById(idTask);
		model.addAttribute("mapUsers", mapUsers);
		model.addAttribute("task", task);
		model.addAttribute("page", "taskedit.jsp");
		return "index";
	}

	@RequestMapping(value = "/taskedit/{idTask}", method = RequestMethod.POST)
	public String editTaskSave(@PathVariable("idTask") Integer idTask,
			@Valid Task task, BindingResult result, Model model) {		
		
		if (!result.hasErrors()) {
			Task taskLoaded = taskService.findTaskById(idTask);
			taskLoaded.setTitle(task.getTitle());
			taskLoaded.setDescription(task.getDescription());
			taskLoaded.setPerformer(task.getPerformer());
			taskLoaded.setResult(task.getResult());
			taskLoaded.setResolved(task.isResolved());
			
			taskService.updateTask(taskLoaded);
			return "redirect:/index";
		}
		model.addAttribute("idTask", idTask);
		model.addAttribute("task", task);
		model.addAttribute("page", "taskedit.jsp");
		return "index";
	}

	@RequestMapping(value = "/registration", method = RequestMethod.GET)
	public String registration(Model model) {
		User user = new User();
		model.addAttribute("user", user);
		model.addAttribute("page", "registration.jsp");
		return "index";
	}

	@RequestMapping(value = "/registration", method = RequestMethod.POST)
	public String registrationsave(@Valid User user, BindingResult result,
			Model model) {

		if (user.getUsername() != null) {
			User userCheck = userService.findByUserName(user.getUsername());
			if (userCheck != null
					&& (userCheck.getUsername() == user.getUsername())) {
				result.rejectValue("username", "Exists.user.username",
						"An account already exists for this username.");
			}
		}

		if (!(user.getPassword().equals(user.getConfirmPassword()))) {
			result.rejectValue("confirmPassword", "Notmatch.user.password",
					"Password and Conform password is not match!");
		}

		if (!result.hasErrors()) {
			user.setPassword(userService.encode(user.getPassword()));
			user.setEnabled(true);
			userService.addUser(user);
			UserRole userRole = new UserRole();
			userRole.setRole("ROLE_USER");
			userRole.setUser(user);
			Set<UserRole> userRoleList = new HashSet<UserRole>();
			user.setUserRole(userRoleList);
			userRoleService.addUserRole(userRole);
			return "redirect:/login";
		}

		model.addAttribute("user", user);
		model.addAttribute("page", "registration.jsp");
		return "index";
	}

	@RequestMapping(value = "/login", method = RequestMethod.GET)
	public ModelAndView login(
			@RequestParam(value = "error", required = false) String error,
			@RequestParam(value = "logout", required = false) String logout,
			HttpServletRequest request) {

		ModelAndView model = new ModelAndView();
		if (error != null) {
			model.addObject("error",
					getErrorMessage(request, "SPRING_SECURITY_LAST_EXCEPTION"));
		}
		if (logout != null) {
			model.addObject("msg", "You've been logged out successfully.");
		}
		model.addObject("page", "login.jsp");
		model.setViewName("index");
		return model;
	}

	private String getErrorMessage(HttpServletRequest request, String key) {

		Exception exception = (Exception) request.getSession()
				.getAttribute(key);

		String error = "";
		if (exception instanceof BadCredentialsException) {
			error = "Invalid username and password!";
		} else if (exception instanceof LockedException) {
			error = exception.getMessage();
		} else {
			error = "Invalid username and password!";
		}
		return error;
	}

	@RequestMapping(value = "/403", method = RequestMethod.GET)
	public ModelAndView accesssDenied() {

		ModelAndView model = new ModelAndView();

		Authentication auth = SecurityContextHolder.getContext()
				.getAuthentication();

		if (!(auth instanceof AnonymousAuthenticationToken)) {
			UserDetails userDetail = (UserDetails) auth.getPrincipal();

			model.addObject("username", userDetail.getUsername());
		}

		model.addObject("page", "403.jsp");

		model.setViewName("index");
		return model;
	}

}

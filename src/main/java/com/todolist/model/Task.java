package com.todolist.model;

import static javax.persistence.GenerationType.IDENTITY;

import java.util.Date;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;

import org.hibernate.validator.constraints.NotEmpty;

@Entity
@Table(name = "task")
public class Task {

	@Id
	@GeneratedValue(strategy = IDENTITY)
	private Integer id;

	@Override
	public String toString() {
		return "Task [id=" + id + ", title=" + title + ", description="
				+ description + ", date=" + date + ", user=" + user
				+ ", performer=" + performer + ", resolved=" + resolved
				+ ", result=" + result + "]";
	}

	@NotEmpty
	private String title;

	@NotEmpty
	private String description;

	private Date date;

	private String user;

	@NotEmpty
	private String performer;

	private boolean resolved;

	private String result;

	public long getId() {
		return id;
	}

	public void setId(Integer id) {
		this.id = id;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public Date getDate() {
		return date;
	}

	public void setDate(Date date) {
		this.date = date;
	}

	public String getResult() {
		return result;
	}

	public void setResult(String result) {
		this.result = result;
	}

	public String getTitle() {
		return title;
	}

	public void setTitle(String title) {
		this.title = title;
	}

	public String getPerformer() {
		return performer;
	}

	public void setPerformer(String performer) {
		this.performer = performer;
	}

	public String getUser() {
		return user;
	}

	public void setUser(String user) {
		this.user = user;
	}

	public boolean isResolved() {
		return resolved;
	}

	public void setResolved(boolean resolved) {
		this.resolved = resolved;
	}

}

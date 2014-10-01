<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%-- <%@ page session="false"%> --%>
<%@ page language="java" contentType="text/html; charset=utf8"
	pageEncoding="utf8"%>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form"%>
<%@ taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
<div>
	<form:form method="POST" commandName="task"
		action="${pageContext.request.contextPath}/index">
		<form:errors path="*" cssClass="errorblock" element="div" />
		<div class="taskform">
			<div class="titleblockform">
				Title:
				<form:input path="title" />
			</div>
			<div class="taskdescriptionform">
				<form:textarea path="description" />
			</div>
			<div class="taskuserform">
				<form:hidden path="user" />
			</div>
			<div class="taskperformerform">
				<form:select path="performer">
					<form:options items="${mapUsers}" />
				</form:select>
			</div>
			<div class="tasksubmitform">
				<input type="submit" />
			</div>
		</div>
	</form:form>
</div>
<div class="taskslist">
	<c:choose>
		<c:when test="${empty requestScope.tasks}">							
				No Tasks in table!!
			</c:when>
		<c:otherwise>
			<c:forEach var="task" items="${requestScope.tasks}">
				<div class="task">
					<div class="titleblock">
						<div class="tasktitle">
							<c:out value="${task.title}" />
						</div>
						<div class="buttonedit">
							<a href="taskedit/${task.id}">Редактировать</a>
						</div>
						<div class="buttondelete">
							<a href="taskdelete/${task.id}">Удалить</a>
						</div>
					</div>
					<div class="taskdescription">
						<c:out value="${task.description}" />
					</div>
					<div class="taskdate">
						<fmt:formatDate type="both" dateStyle="medium" timeStyle="medium"
							value="${task.date}" />
					</div>

					<c:choose>
						<c:when test="${task.resolved==true}">
							<div class="taskstatus">Выполнено!</div>
						</c:when>
						<c:otherwise>
							<div class="taskstatusnotresolved">Не выполнено</div>
						</c:otherwise>
					</c:choose>

					<div class="taskuser">
						Создал:
						<c:out value="${task.user}" />
					</div>
					<div class="taskperformer">
						Исполняет:
						<c:out value="${task.performer}" />
					</div>
				</div>
			</c:forEach>
		</c:otherwise>
	</c:choose>
</div>
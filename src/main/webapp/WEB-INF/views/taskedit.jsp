<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%-- <%@ page session="false"%> --%>
<%@ page language="java" contentType="text/html; charset=utf8"
	pageEncoding="utf8"%>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form"%>
<%@ taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<div>
	<form:form method="POST" commandName="task"
		action="${pageContext.request.contextPath}/taskedit/${idTask}">
		<form:errors path="*" cssClass="errorblock" element="div" />
		<div class="taskformedit">
			<div class="titleblockform">
				Title:
				<form:input path="title" />
			</div>
			<div class="taskdescriptionform">
				<form:textarea path="description" />
			</div>			
			<div class="taskperformerform">
				<form:select path="performer">
					<form:options items="${mapUsers}" />
				</form:select>
			</div>
			<div class="taskresolvedform">
				<form:checkbox path="resolved" value="true" checked="checked" />
				Resolved?
			</div>
			<div class="taskresultform">
				<form:textarea path="result" />
			</div>
			<div class="tasksubmitformedit">
				<input type="submit" />
			</div>
		</div>
	</form:form>
</div>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%-- <%@ page session="false"%> --%>
<%@ page language="java" contentType="text/html; charset=utf8"
	pageEncoding="utf8"%>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form"%>
<%@ taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<html>
<head>
<title>Task manager</title>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<link href="<c:url value="/resources/todolist.css" />" rel="stylesheet">
<script src="<c:url value="/resources/todolist.js" />"></script>
</head>
<body>
	<div id="mainblock">
		<h1>
			<spring:message code="label.indexname" />
		</h1>
		<div id="loginblock">
			<c:choose>
				<c:when test="${pageContext.request.userPrincipal.name != null}">
					<spring:message code="label.welcome" /> ,  ${pageContext.request.userPrincipal.name} | <a
						href="<c:url value="/logout"/>"> <spring:message
							code="label.logout" /></a>
				</c:when>
				<c:otherwise>
					<form name='loginForm'
						action="<c:url value='/j_spring_security_check' />" method='POST'>
						<div id="usernamelogin">
							<spring:message code="label.login" />
						</div>
						<div id="input">
							<label> <input type='text' class="input"
								name='j_username' />
							</label>
						</div>
						<div id="passwordlogin">
							<spring:message code="label.password" />
						</div>
						<div id="input02">
							<label> <input type='password' name='j_password' />
							</label>
						</div>
						<div id="loginbutton">
							<input name="submit" type="submit"
								value="<spring:message code="label.enter" />" />
						</div>
						<div id="member">

							<spring:message code="label.notyetamamber" />
							<a href="<c:url value="/registration" />"> <spring:message
									code="label.registernow" /></a>
						</div>
					</form>
				</c:otherwise>
			</c:choose>
		</div>
		<div id="menu">
			menu  <br> <a href="<c:url value="/index" />"> <spring:message
					code="label.main" /></a>
		</div>
		<div id="content">

			<jsp:include page="${page}"></jsp:include>
		</div>
	</div>
</body>
</html>

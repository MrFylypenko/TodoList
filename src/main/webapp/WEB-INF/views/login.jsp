<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%-- <%@ page session="false"%> --%>
<%@ page language="java" contentType="text/html; charset=utf8"
	pageEncoding="utf8"%>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form"%>
<%@ taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<div id="login-box">
	<h3>
		<spring:message code="label.loginwithusernameandpassword" />
	</h3>
	<c:if test="${not empty error}">
		<div class="error">
			<spring:message code="label.invalidusernameandpassword" />
		</div>
	</c:if>
	<c:if test="${not empty msg}">
		<div class="msg">${msg}</div>
	</c:if>

	<form name='loginForm'
		action="<c:url value='/j_spring_security_check' />" method='POST'>
		<table>
			<tr>
				<td><spring:message code="label.login" />:</td>
				<td><input type='text' name='j_username'></td>
			</tr>
			<tr>
				<td><spring:message code="label.password" />:</td>
				<td><input type='password' name='j_password' /></td>
			</tr>
			<tr>
				<td colspan='2'><input name="submit" type="submit"
					value="<spring:message code="label.enter" />" /></td>
			</tr>
		</table>
	</form>
</div>

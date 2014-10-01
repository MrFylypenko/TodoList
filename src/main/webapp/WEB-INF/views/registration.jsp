<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%-- <%@ page session="false"%> --%>
<%@ page language="java" contentType="text/html; charset=utf8"
	pageEncoding="utf8"%>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form"%>
<%@ taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<h2>
	<spring:message code="label.userregistration" />
</h2>

<div>
	<form:form method="POST" commandName="user"
		action="${pageContext.request.contextPath}/registration">
		<form:errors path="*" cssClass="errorblock" element="div" />
		<table>
			<tr>
				<td><spring:message code="label.login" /> :</td>
				<td><form:input path="username" /></td>
				<td><form:errors path="username" cssClass="errortext" /></td>
			</tr>
			<tr>
				<td><spring:message code="label.password" /> :</td>
				<td><form:password path="password" /></td>
				<td><form:errors path="password" cssClass="errortext" /></td>
			</tr>
			<tr>
				<td><spring:message code="label.confirmpassword" /> :</td>
				<td><form:password path="confirmPassword" /></td>
				<td><form:errors path="confirmPassword" cssClass="errortext" /></td>
			</tr>
			<tr>
				<td><spring:message code="label.email" /> :</td>
				<td><form:input path="email" /></td>
				<td><form:errors path="email" cssClass="errortext" /></td>
			</tr>
			<tr>
				<td colspan="3"><input type="submit" value="<spring:message code="label.register" />"/></td>
			</tr>
		</table>
	</form:form>

</div>
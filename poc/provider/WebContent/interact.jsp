<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@page import="dk.itst.oiosaml.sp.UserAssertionHolder"%><html>
<jsp:include page="head.jsp" />

<h1>Welcome, <%= UserAssertionHolder.get().getSubject() %>!</h1>

<p>To process further requests, you need to provide additional information.</p>

<p>Please enter info below: <br />
<form method="post" action="interact">
<input type="text" name="info" /><br />
<input type="submit" value="Send" />

<input type="hidden" name="ReturnToURL" value="<%= request.getParameter("ReturnToURL") %>" />
</form>
</p>
